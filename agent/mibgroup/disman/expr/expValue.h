
#ifndef EXPVALUE_H
#define EXPVALUE_H

#include "disman/expr/expExpression.h"

netsnmp_variable_list *
expValue_evaluateExpression( struct expExpression *exp,
                             oid *suffix, size_t suffix_len );

#endif                          /* EXPVALUE_H */
