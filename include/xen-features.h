#ifndef __XEN_FEATURES_H__
#define __XEN_FEATURES_H__

#include <xen/features.h>

extern uint8_t xen_features[XENFEAT_NR_SUBMAPS * 32];
static inline int xen_feature(int flag)
{
    return xen_features[flag];
}

#endif /* __ASM_XEN_FEATURES_H__ */
