#ifndef AUTONLIST_H

struct autonlist {
   char symbol[128];
   struct nlist nl[2];
   struct autonlist *left, *right;
};

#define AUTONLIST_H
#endif
