#pragma once
#include<Windows.h>
#include<iostream>

typedef struct _MEMBLOCK
{
	HANDLE hProcess;
	PVOID addr;		 //�ڴ���ַ
	int size;		 //�ڴ���С
	char* buffer;	 //�ڴ�����

	char* searchmask;//������ʶ������ʶÿһ�ֽڵ������Ƿ��������б���
	int matches;	 //ƥ������ݸ���
	int data_size;   //���ݴ�С(��λ�ֽ�)
	struct _MEMBLOCK* next;
}MEMBLOCK;

typedef enum
{
	COND_UNCONDITIONAL, //ÿ���ֽ�
	COND_EQUALS,		//��ֵΪ�ض�ֵ���ֽ�
	COND_INCREASE,		//��ֵ������ֽ�
	COND_DECREASE,		//��ֵ��С���ֽ�
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