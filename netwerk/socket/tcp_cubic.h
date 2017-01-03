/* -*- Mode: C++; tab-width: 2; indent-tabs-mode: nil; c-basic-offset: 2 -*- */

#ifndef CUBIC_H
#define CUBIC_H

#include <stdint.h>
#include "prinrval.h"
#include "congestion_control.h"

extern struct sdt_congestion_control_variation_ops cubic_cc;

extern struct sdt_slowstart_variation_ops hystart;

#endif // CUBIC_H
