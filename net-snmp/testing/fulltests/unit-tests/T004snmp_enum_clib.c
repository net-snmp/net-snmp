#define STRING1 "life, and everything"
#define STRING2 "resturant at the end of the universe"

init_snmp_enum("snmp");
se_add_pair(1, 1, "hi", 1);
se_add_pair(1, 1, "there", 2);

OK(se_find_value(1, 1, "hi") == 1,
   "lookup by number #1 should be the proper string");
OK(strcmp(se_find_label(1, 1, 2), "there") == 0,
   "lookup by string #1 should be the proper number");


se_add_pair_to_slist("testing", STRING1, 42);
se_add_pair_to_slist("testing", STRING2, 2);
    
OK(se_find_value_in_slist("testing", STRING1) == 42,
   "lookup by number should be the proper string");
OK(strcmp(se_find_label_in_slist("testing", 2), STRING2) == 0,
   "lookup by string should be the proper number");

