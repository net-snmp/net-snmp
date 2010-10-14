/* HEADER Testing snmp_enum */

#define STRING1 "life, and everything"
#define STRING2 "restaurant at the end of the universe"
#define STRING3 "label3"

char *se_find_result;

init_snmp_enum("snmp");
se_add_pair(1, 1, strdup("hi"), 1);
se_add_pair(1, 1, strdup("there"), 2);

OK(se_find_value(1, 1, "hi") == 1,
   "lookup by number #1 should be the proper string");
OK(strcmp(se_find_label(1, 1, 2), "there") == 0,
   "lookup by string #1 should be the proper number");


se_add_pair_to_slist("testing", strdup(STRING1), 42);
se_add_pair_to_slist("testing", strdup(STRING2), 2);
se_add_pair_to_slist("testing", strdup(STRING3), 2);
    
OK(se_find_value_in_slist("testing", STRING1) == 42,
   "lookup by number should be the proper string");
OK(strcmp(se_find_label_in_slist("testing", 2), STRING2) == 0,
   "lookup by string should be the proper number");

se_clear_slist("testing");


se_read_conf("enum",
             NETSNMP_REMOVE_CONST(char *, "2:3 1:apple 2:pear 3:kiwifruit"));
OK(se_find_list(2, 3), "list (2, 3) should be present");
if (se_find_list(2, 3)) {
  OK(se_find_value(2, 3, "kiwifruit") == 3,
     "lookup by string should return the proper value")
  se_find_result = se_find_label(2, 3, 2);
  OK(se_find_result && strcmp(se_find_result, "pear") == 0,
     "lookup by label should return the proper string")
}

se_read_conf("enum",
             NETSNMP_REMOVE_CONST(char *, "fruit 1:apple 2:pear 3:kiwifruit"));
OK(se_find_value_in_slist("fruit", "kiwifruit") == 3,
   "lookup by string should return the proper value");
se_find_result = se_find_label_in_slist("fruit", 2);
OK(se_find_result && strcmp(se_find_result, "pear") == 0,
   "lookup by value should return the proper string");

clear_snmp_enum();
unregister_all_config_handlers();
