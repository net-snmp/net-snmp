#define STRMAX 1000
#define SHPROC 1
#define EXECPROC 2


struct extensible
{
   char name[STRMAX];
   char command[STRMAX];
   int type;
   long result;
   char output[STRMAX];
   struct extensible *next;
};

struct myproc
{
  char name[STRMAX];
  int min;
  int max;
  struct myproc *next;
};

struct mibinfo 
{
   int numid;
   unsigned long mibid[10];
   char *name;
   void (*handle) ();
};


