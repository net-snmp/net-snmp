/* hp-port:  needed random defs and htonl and htons defs */

#ifdef hpux
int random()
{
  return(rand());
}

void srandom(seed)
  unsigned int seed;
{
  srand(seed);
}

#endif
