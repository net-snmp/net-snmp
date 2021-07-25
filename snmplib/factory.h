#ifndef NETSNMP_FACTORY_H
#define NETSNMP_FACTORY_H

#ifdef __cplusplus
extern "C" {
#elif 0
}
#endif

typedef void * (netsnmp_factory_produce_f)(void);

typedef struct netsnmp_factory_s {
    /*
     * a string describing the product the factory creates
     */
    const char                           *product;

    /*
     * a function to create an object in newly allocated memory
     */
    netsnmp_factory_produce_f            *produce;
} netsnmp_factory;

#ifdef __cplusplus
}
#endif

#endif /* NETSNMP_FACTORY_H */
