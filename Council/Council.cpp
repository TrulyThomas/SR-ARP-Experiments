#include <stdio.h>
#include <iostream>
#include <stdlib.h>
#include <time.h>
#include <string.h>
#include <windows.h>

double PCFreq = 0.0;
__int64 CounterStart = 0;

void StartCounter()
{
	LARGE_INTEGER li;
	if (!QueryPerformanceFrequency(&li))
		std::cout << "QueryPerformanceFrequency failed!\n";

	PCFreq = double(li.QuadPart) / 1000000.0;

	QueryPerformanceCounter(&li);
	CounterStart = li.QuadPart;
}
double GetCounter()
{
	LARGE_INTEGER li;
	QueryPerformanceCounter(&li);
	return double(li.QuadPart - CounterStart) / PCFreq;
}
typedef struct
{
	int mac[6];
	int mac_res[6];
} host_t;

typedef struct
{
	int** mac;
	int* reputation;
} host_dict_t;

typedef struct
{
	int** mac;
	int* vote;
} vote_dict_t;

void print_host(host_t host)
{
	int i;

	for (i = 0; i < 6; i++)
		if (i < 5)
			printf("%02x:", host.mac[i]);
		else
			printf("%02x ", host.mac[i]);

	for (i = 0; i < 6; i++)
		if (i < 5)
			printf("%02x:", host.mac_res[i]);
		else
			printf("%02x\n", host.mac_res[i]);
}
void print_dict(vote_dict_t d, int size)
{
	int i, j;
	for (i = 0; i < size; i++)
	{
		for (j = 0; j < 6; j++)
		{
			if (j < 5)
				printf("%02x:", d.mac[i][j]);
			else
				printf("%02x |", d.mac[i][j]);
		}
		printf(" %i\n", d.vote[i]);
	}
}

// Signature:   voter-n
int main()
{

	int n = 50;
	srand((unsigned)time(NULL));

	// Arrange votess
	host_t* voters = (host_t*)malloc(n * sizeof(*voters));
	host_dict_t rep_voter_dict;

	rep_voter_dict.mac = (int**)malloc(sizeof(*rep_voter_dict.mac) * 6 * n);
	rep_voter_dict.reputation = (int*)malloc(sizeof(*rep_voter_dict.reputation) * n);
	int i, j;
	int mac_res[6] = { 236, 242, 42, 16, 58, 38 };
	// init voters
	for (i = 0; i < n; i++)
	{
		for (j = 0; j < 6; j++)
		{
			voters[i].mac[j] = rand() % 256;
			voters[i].mac_res[j] = mac_res[j];
		}
		rep_voter_dict.mac[i] = voters[i].mac;
		rep_voter_dict.reputation[i] = rand() % 101;
	}


	StartCounter();

	// handle votes
	vote_dict_t votes;
	votes.mac = (int**)malloc(sizeof(*votes.mac) * 6 * n);
	votes.vote = (int*)malloc(sizeof(*votes.vote) * n);

	int count = 1;
	int notvoted = 1;
	votes.mac[0] = voters[0].mac_res;
	votes.vote[0] = rep_voter_dict.reputation[0];
	for (i = 1; i < n; i++)
	{
		for (j = 0; j < count; j++)
		{
			if (memcmp(votes.mac[j], voters[i].mac_res, sizeof(int) * 6) == 0) {
				votes.vote[j] += rep_voter_dict.reputation[i];
				notvoted = 0;
			}
		}
		if (notvoted) {
			votes.vote[count] = rep_voter_dict.reputation[i];
			votes.mac[count++] = voters[i].mac_res;
		}
		notvoted = 1;
	}

	// stop timer
	std::cout << GetCounter() << "\n";

	return 0;
}

