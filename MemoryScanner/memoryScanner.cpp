#include"memoryScanner.h"
using namespace std;

#define IS_IN_SEARCH(mb,offset) (mb->searchmask[(offset)/8] & (1<<((offset)%8)))
#define REMOVE_FROM_SEARCH(mb,offset) mb->searchmask[(offset)/8]&=~(1<<((offset)%8));


int main()
{
	
	ui_run_scan();

	return 0;
}


MEMBLOCK* create_memblock(HANDLE hProcess, MEMORY_BASIC_INFORMATION* meminfo, int data_size)
{
	MEMBLOCK* mb = (MEMBLOCK*)malloc(sizeof(MEMBLOCK));
	if (mb)
	{
		mb->hProcess = hProcess;
		mb->addr = meminfo->BaseAddress;
		mb->size = meminfo->RegionSize;
		mb->buffer = (char*)malloc(meminfo->RegionSize);

		//初始化搜索掩码为0xff，表示每一个字节都在搜索列表中
		mb->searchmask = (char*)malloc(meminfo->RegionSize / 8);
		memset(mb->searchmask, 0xff, meminfo->RegionSize / 8);

		mb->matches = meminfo->RegionSize;
		mb->data_size = data_size;
		mb->next = NULL;
	}

	return mb;
}
void update_memblock(MEMBLOCK* mb, SEARCH_CONDITION condition, int val)
{
	static unsigned char tempbuf[128 * 1024];//0x20000
	unsigned int bytes_left;//当前未处理的字节数
	unsigned int total_read;//已经处理的字节数
	unsigned int bytes_to_read;
	SIZE_T bytes_read;

	if (mb->matches > 0)
	{
		bytes_left = mb->size;
		total_read = 0;

		mb->matches = 0;

		while (bytes_left)
		{
			bytes_to_read = (bytes_left > sizeof(tempbuf)) ? sizeof(tempbuf) : bytes_left;
			ReadProcessMemory(mb->hProcess, (LPCVOID)((SIZE_T)mb->addr + total_read), tempbuf, bytes_to_read, &bytes_read);
			//如果读失败了，则结束
			if (bytes_to_read != bytes_read) break;

			//条件搜索处
			if (condition == COND_UNCONDITIONAL)//无条件，则所有数据都匹配
			{
				memset(mb->searchmask + total_read / 8, 0xff, bytes_read / 8);
				mb->matches += bytes_read;
			}
			else//遍历临时buffer
			{
				for (int offset = 0; offset < bytes_read; offset += mb->data_size)
				{
					if (IS_IN_SEARCH(mb, (total_read + offset)))
					{
						BOOL is_match = FALSE;
						int temp_val;
						int prev_val;
						switch (mb->data_size)//获取临时数值的大小
						{
						case 1:
							temp_val = tempbuf[offset];
							prev_val = *((char*)&mb->buffer[total_read + offset]);
							break;
						case 2:
							temp_val = *((short*)&tempbuf[offset]);
							prev_val = *((short*)&mb->buffer[total_read + offset]);
							break;
						case 4:
						default:
							temp_val = *((int*)&tempbuf[offset]);
							prev_val = *((short*)&mb->buffer[total_read + offset]);
							break;
						}

						switch (condition)//根据不同搜索条件处理
						{
						case COND_EQUALS:
							is_match = (temp_val == val);
							break;
						case COND_INCREASE:
							is_match = (temp_val > prev_val);
							break;
						case COND_DECREASE:
							is_match = (temp_val < prev_val);
							break;
						default:
							break;
						}

						if (is_match)
						{
							mb->matches++;
						}
						else
						{
							REMOVE_FROM_SEARCH(mb, (total_read + offset));
						}
					}
				}
			}


			memcpy(mb->buffer + total_read, tempbuf, bytes_read);

			bytes_left -= bytes_read;
			total_read += bytes_read;
		}
		mb->size = total_read;

	}
}
void free_memblock(MEMBLOCK* mb)
{
	if (mb)
	{
		if (mb->buffer)
		{
			free(mb->buffer);
		}
		if (mb->searchmask)
		{
			free(mb->searchmask);
		}
		free(mb);
	}
}


MEMBLOCK* create_scan(int pid, int data_size)
{
	MEMBLOCK* mb_list = NULL;
	MEMORY_BASIC_INFORMATION meminfo;
	PVOID addr = 0;

	HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
	if (hProcess)
	{
		while (1)
		{
			//查询失败，返回
			if (!VirtualQueryEx(hProcess, addr, &meminfo, sizeof(meminfo)))
			{
				break;
			}
#define WRITABLE (PAGE_READWRITE|PAGE_WRITECOPY|PAGE_EXECUTE_READWRITE|PAGE_EXECUTE_WRITECOPY)

			if ((meminfo.State & MEM_COMMIT) && (meminfo.Protect & WRITABLE))
			{
				MEMBLOCK* mb = create_memblock(hProcess, &meminfo, data_size);
				//头插法将扫描的内存块存入内存块列表中
				if (mb)
				{
					mb->next = mb_list;
					mb_list = mb;
				}
			}

			addr = (LPVOID)((SIZE_T)meminfo.BaseAddress + meminfo.RegionSize);
		}
	}

	return mb_list;
}
void update_scan(MEMBLOCK* mb_list, SEARCH_CONDITION condition, int val)
{
	MEMBLOCK* mb = mb_list;
	while (mb)
	{
		update_memblock(mb, condition, val);
		mb = mb->next;
	}
}
void free_scan(MEMBLOCK* mb_list)
{
	CloseHandle(mb_list->hProcess);
	while (mb_list)
	{
		MEMBLOCK* mb = mb_list;
		mb_list = mb_list->next;
		free_memblock(mb);
	}
}
void dump_scan_info(MEMBLOCK* mb_list)
{
	MEMBLOCK* mb = mb_list;
	while (mb)
	{
		//打印内存块
		printf("0x%08x 0x%08x\r\n", mb->addr, mb->size);

		mb = mb->next;

		//打印内存块中数据
		for (int i = 0; i < mb->size; i++)
		{
			printf("0x%02x ", mb->buffer[i]);
			if (i % 16 == 0) printf("\r\n");
		}
		printf("\r\n");
	}
}


void poke(HANDLE hProcess, int data_size, PVOID addr, int val)//写内存
{
	if (!WriteProcessMemory(hProcess, addr, &val, data_size, NULL))
	{
		printf("poke failed\r\n");
	}
}
int peek(HANDLE hProcess, int data_size, PVOID addr)
{
	int val = 0;
	if (!ReadProcessMemory(hProcess, addr, &val, data_size, NULL))
	{
		printf("peek failed\r\n");
	}
	return val;
}


void print_matches(MEMBLOCK* mb_list)
{
	MEMBLOCK* mb = mb_list;
	while (mb)
	{
		for (int offset = 0; offset < mb->size; offset += mb->data_size)
		{
			if (IS_IN_SEARCH(mb, offset))
			{
				int val = peek(mb->hProcess, mb->data_size, (PVOID)((SIZE_T)mb->addr + offset));
				printf("0x%08x : %d\r\n", (SIZE_T)mb->addr + offset, val);
			}
		}
		mb = mb->next;
	}
}
int get_match_count(MEMBLOCK* mb_list)
{
	MEMBLOCK* mb = mb_list;
	int count = 0;
	while (mb)
	{
		count += mb->matches;
		mb = mb->next;
	}
	return count;
}


int str2int(char* s)
{
	int base = 10;
	if (s[0] == '0' && s[1] == 'x')
	{
		base = 16;
		s += 2;
	}
	return strtol(s, NULL, base);
}


MEMBLOCK* ui_new_scan(void)
{
	MEMBLOCK* scan = NULL;
	DWORD pid;
	int data_size;
	int start_val;
	SEARCH_CONDITION start_cond;
	char s[20];

	while (1)
	{
		printf("\r\nEnter the pid:");
		fgets(s, sizeof(s), stdin);
		pid = str2int(s);
		printf("\r\nEnter the data size:");
		fgets(s, sizeof(s), stdin);
		data_size = str2int(s);
		printf("\r\nEnter the start value or 'u' for unknown:");
		fgets(s, sizeof(s), stdin);
		if (s[0] == 'u')
		{
			start_cond = COND_UNCONDITIONAL;
			start_val = 0;
		}
		else
		{
			start_cond = COND_EQUALS;
			start_val = str2int(s);
		}

		scan = create_scan(pid, data_size);
		if (scan) break;//如果创建成功，则退出
		printf("\r\n invalid scan");
	}
	update_scan(scan, start_cond, start_val);
	printf("\r\n %d matches found\r\n", get_match_count(scan));

	return scan;
}
void ui_poke(HANDLE hProcess, int data_size)
{
	int addr;
	int val;
	char s[20];

	printf("Enter the address:");
	fgets(s, sizeof(s), stdin);
	addr = str2int(s);

	printf("Enter the value:");
	fgets(s, sizeof(s), stdin);
	val = str2int(s);

	poke(hProcess, data_size, (PVOID)addr, val);
}
void ui_run_scan()
{
	int val;
	char s[20];
	MEMBLOCK* scan;

	scan = ui_new_scan();

	while (1)
	{
		printf("\r\n Enter the next value or");
		printf("\r\n[i] increased");
		printf("\r\n[d] decreased");
		printf("\r\n[m] print matches");
		printf("\r\n[p] poke address");
		printf("\r\n[n] new scan");
		printf("\r\n[q] quit\r\n");

		fgets(s, sizeof(s), stdin);
		printf("\r\n");

		switch (s[0])
		{
		case 'i':
			update_memblock(scan, COND_INCREASE, 0);
			printf("%d matches found\r\n", get_match_count(scan));
			break;
		case 'd':
			update_memblock(scan, COND_DECREASE, 0);
			printf("%d matches found\r\n", get_match_count(scan));
			break;
		case 'm':
			print_matches(scan);
			break;
		case 'p':
			ui_poke(scan->hProcess, scan->data_size);
			break;
		case 'n':
			free(scan);
			scan = ui_new_scan();
			break;
		case 'q':
			free(scan);
			return;
		default:
			val = str2int(s);
			update_scan(scan, COND_EQUALS, val);
			printf("%d matches found\r\n", get_match_count(scan));
			break;

		}
	}
}
