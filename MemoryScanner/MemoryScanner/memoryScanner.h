#pragma once
#include<Windows.h>
#include<iostream>

typedef struct _MEMBLOCK
{
	HANDLE hProcess;
	PVOID addr;		 //内存块地址
	int size;		 //内存块大小
	char* buffer;	 //内存数据

	char* searchmask;//搜索标识符，标识每一字节的数据是否在搜索列表中
	int matches;	 //匹配的数据个数
	int data_size;   //数据大小(单位字节)
	struct _MEMBLOCK* next;
}MEMBLOCK;

typedef enum
{
	COND_UNCONDITIONAL, //每个字节
	COND_EQUALS,		//数值为特定值的字节
	COND_INCREASE,		//数值增大的字节
	COND_DECREASE,		//数值减小的字节
}SEARCH_CONDITION;


MEMBLOCK* create_memblock(HANDLE hProcess, MEMORY_BASIC_INFORMATION* meminfo, int data_size);
void update_memblock(MEMBLOCK* mb, SEARCH_CONDITION condition, int val);
void free_memblock(MEMBLOCK* mb);


MEMBLOCK* create_scan(int pid, int data_size);
void update_scan(MEMBLOCK* mb_list, SEARCH_CONDITION condition, int val);
void free_scan(MEMBLOCK* mb_list);
void dump_scan_info(MEMBLOCK* mb_list);

void poke(HANDLE hProcess, int data_size, PVOID addr, int val);
int peek(HANDLE hProcess, int data_size, PVOID addr);

void print_matches(MEMBLOCK* mb_list);
int get_match_count(MEMBLOCK* mb_list);


int str2int(char* s);


//ui
MEMBLOCK* ui_new_scan(void);
void ui_poke(HANDLE hProcess, int data_size);
void ui_run_scan();