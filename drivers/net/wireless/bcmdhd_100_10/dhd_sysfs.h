/*
 * Copyright (C) 2019, cocafe <cocafehj@gmail.com>
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include <dhd.h>

#include <linux/types.h>
#include <linux/atomic.h>

extern atomic_t dhd_pm_resume;
extern atomic_t dhd_pm_suspend;

int bcmdhd_sysfs_init(dhd_pub_t *dhd);
void bcmdhd_sysfs_deinit(void);