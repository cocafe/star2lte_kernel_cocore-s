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
#include <dhd_linux.h>
#include <dhd_linux_priv.h>
#include <wldev_common.h>
#include <wl_cfg80211.h>

#include <linux/mm.h>
#include <linux/slab.h>
#include <linux/types.h>
#include <linux/atomic.h>
#include <linux/kernel.h>
#include <linux/kobject.h>

static dhd_pub_t *p_dhd;

struct ioctl_op {
	const char 	*cmd;
	const size_t 	cmdlen;
	const char 	*fmt;
	const size_t 	argc;
};

enum ioctl_op_idx {
	CMD_SET = 0,
	CMD_GET,
	CMD_BUF_ALLOC,
	CMD_BUF_FREE,
	NR_IOCTL_CMDS,
};

static const struct ioctl_op ioctl_ops[] = {
	{ "set", 	3, "set %d", 		1 },
	{ "get", 	3, "get %d", 		1 },
	{ "alloc", 	5, "alloc %zu", 	1 },
	{ "free",	4, NULL, 		0 },
};

static char *ioctl_buf = NULL;
static size_t ioctl_bufsz = 0;

DEFINE_MUTEX(ioctl_mutex);

static const char *pm_mode_str[] = {
	"pm_off (ps off)",	// powersave disabled
	"pm_max (ps on)",	// powersave mode
	"pm_fast (ps fast)",	// powersave fast?
	"pm_alloff",
};

// FIXME: these values can be applied to hw only when earlysuspend triggers
atomic_t dhd_pm_resume = ATOMIC_INIT(PM_FAST);
atomic_t dhd_pm_suspend = ATOMIC_INIT(PM_FAST);

static const char *band_str[] = {
	"auto",
	"5G",
	"2G",
	"all bands",
	"6G",
};

int ioctl_cmd_rw(int iocmd, int write)
{
	if (!ioctl_buf)
		return -ENODATA;

	if (dhd_wl_ioctl_cmd(p_dhd, iocmd, ioctl_buf, ioctl_bufsz, !!write, 0))
		return -EIO;

	return 0;
}

// TODO: mutex lock
void ioctl_buf_free(void)
{
	if (ioctl_buf) {
		kfree(ioctl_buf);

		ioctl_buf = NULL;
		ioctl_bufsz = 0;
	}
}

// FIXME: sz is not checked and limited
int ioctl_buf_alloc(size_t sz)
{
	ioctl_buf_free();

	ioctl_buf = kcalloc(1, sz, GFP_KERNEL);
	if (!ioctl_buf) {
		pr_err("%s: no available memory\n", __func__);
		return -ENOMEM;
	}

	ioctl_bufsz = sz;

	return 0;
}

static ssize_t ioctl_cmd_show(struct kobject *kobj, struct kobj_attribute *attr, char *buf)
{
	return sprintf(buf, "set [ioctl_cmd(dec)]\n"
		            "get [ioctl_cmd(dec)]\n"
		            "alloc [bufsz]\n"
		            "free\n");
}

static ssize_t ioctl_cmd_store(struct kobject *kobj, struct kobj_attribute *attr,
                               const char *buf, size_t count)
{
	const struct ioctl_op *io_op;
	size_t buflen;
	size_t iobufsz;
	int cmd;
	int idx;
	int err = 0;

	if (!mutex_trylock(&ioctl_mutex))
		return -EBUSY;

	buflen = strlen(buf);

	for (idx = 0; idx < NR_IOCTL_CMDS; idx++) {
		io_op = &ioctl_ops[idx];
		err = strncmp(buf, io_op->cmd,
		              buflen > io_op->cmdlen ? io_op->cmdlen : buflen);
		if (!err)
			break;
	}

	if (idx == NR_IOCTL_CMDS) {
		pr_err("%s: invalid cmd\n", __func__);
		err = -EINVAL;

		goto out;
	}

	switch (idx) {
		case CMD_SET:
		case CMD_GET:
			if (sscanf(buf, io_op->fmt, &cmd) != io_op->argc) {
				pr_err("%s: invalid format\n", __func__);
				err = -EINVAL;

				goto out;
			}

			if ((err = ioctl_cmd_rw(cmd, (idx == CMD_SET) ? 1 : 0))) {
				pr_err("%s: dhd ioctl() failed: %d\n", __func__, err);
				goto out;
			}

			break;

		case CMD_BUF_ALLOC:
			if (sscanf(buf, io_op->fmt, &iobufsz) != io_op->argc) {
				pr_err("%s: invalid format\n", __func__);
				err = -EINVAL;

				goto out;
			}

			if ((err = ioctl_buf_alloc(iobufsz))) {
				pr_err("%s: failed to alloc buffer: %d\n", __func__, err);
				goto out;
			}

			break;

		case CMD_BUF_FREE:
			ioctl_buf_free();
			break;

		default:
			return -EFAULT;
	}

out:
	mutex_unlock(&ioctl_mutex);

	if (err)
		return err;

	return count;
}

static ssize_t ioctl_buf_show(struct kobject *kobj, struct kobj_attribute *attr, char *buf)
{
	size_t cpsz;

	if (!mutex_trylock(&ioctl_mutex))
		return -EBUSY;

	if (!ioctl_buf) {
		mutex_unlock(&ioctl_mutex);
		return -ENODATA;
	}

	if (ioctl_bufsz >= sizeof(int))
		pr_info("%s: 0x%08x\n", __func__, *(int *)ioctl_buf);

	cpsz = ioctl_bufsz < (PAGE_SIZE - 1) ? ioctl_bufsz : (PAGE_SIZE - 1);
	memcpy(buf, ioctl_buf, cpsz);

	mutex_unlock(&ioctl_mutex);

	return cpsz;
}

static ssize_t ioctl_buf_store(struct kobject *kobj, struct kobj_attribute *attr,
                               const char *buf, size_t count)
{
	int err = 0;

	if (!mutex_trylock(&ioctl_mutex))
		return -EBUSY;

	if (!ioctl_buf) {
		err = -ENODATA;
		goto out;
	}

	pr_info("%s: input byte count: %zu\n", __func__, count);

	if (count > ioctl_bufsz) {
		pr_err("%s: ioctl buffer size is unable to hold input buffer\n", __func__);

		err = -EINVAL;
		goto out;
	}

	memcpy(ioctl_buf, buf, count);

out:
	mutex_unlock(&ioctl_mutex);

	if (err)
		return err;

	return count;
}

static ssize_t ioctl_bufsz_show(struct kobject *kobj, struct kobj_attribute *attr, char *buf)
{
	int ret;

	if (!mutex_trylock(&ioctl_mutex))
		return -EBUSY;

	ret = scnprintf(buf, PAGE_SIZE - 1, "%zu\n", ioctl_bufsz);

	mutex_unlock(&ioctl_mutex);

	return ret;
}

static ssize_t ioctl_bufint_show(struct kobject *kobj, struct kobj_attribute *attr, char *buf)
{
	int ret;

	if (!mutex_trylock(&ioctl_mutex))
		return -EBUSY;

	if (!ioctl_buf) {
		ret = -ENODATA;
		goto out;
	}

	if (ioctl_bufsz < sizeof(int)) {
		ret = -EINVAL;
		goto out;
	}

	ret = scnprintf(buf, PAGE_SIZE - 1, "0x%08x\n", *(int *)ioctl_buf);

out:
	mutex_unlock(&ioctl_mutex);

	return ret;
}

static ssize_t ioctl_bufint_store(struct kobject *kobj, struct kobj_attribute *attr,
                               const char *buf, size_t count)
{
	int val;
	int ret = 0;

	if (!mutex_trylock(&ioctl_mutex))
		return -EBUSY;

	if (!ioctl_buf) {
		ret = -ENODATA;
		goto out;
	}

	if (ioctl_bufsz < sizeof(int)) {
		ret = -ENOMEM;
		goto out;
	}

	if (sscanf(buf, "%x", &val) != 1) {
		ret = -EINVAL;
		goto out;
	}

	memcpy(ioctl_buf, &val, sizeof(int));

out:
	mutex_unlock(&ioctl_mutex);

	if (ret)
		return ret;

	return count;
}

static struct kobj_attribute ioctl_cmd_interface =
	__ATTR(ioctl, 0600, ioctl_cmd_show, ioctl_cmd_store);

static struct kobj_attribute ioctl_buf_interface =
	__ATTR(ioctl_buf, 0600, ioctl_buf_show, ioctl_buf_store);

static struct kobj_attribute ioctl_bufsz_interface =
	__ATTR(ioctl_bufsz, 0400, ioctl_bufsz_show, NULL);

static struct kobj_attribute ioctl_bufint_interface =
	__ATTR(ioctl_bufint, 0600, ioctl_bufint_show, ioctl_bufint_store);

static struct attribute *dhd_sysfs_ioctl_attrs[] = {
	&ioctl_cmd_interface.attr,
	&ioctl_buf_interface.attr,
	&ioctl_bufsz_interface.attr,
	&ioctl_bufint_interface.attr,
	NULL,
};

static struct attribute_group dhd_sysfs_ioctl_ifgroup = {
	.name  = "ioctl",
	.attrs = dhd_sysfs_ioctl_attrs,
};

static ssize_t dhd_pm_show(struct kobject *kobj, struct kobj_attribute *attr, char *buf)
{
	int val, err;

	err = dhd_wl_ioctl_cmd(p_dhd, WLC_GET_PM, (char *)&val, sizeof(val), FALSE, 0);
	if (err)
		return -EIO;

	if (val <= (ARRAY_SIZE(pm_mode_str) - 1))
		return scnprintf(buf, PAGE_SIZE - 1, "%d: %s\n", val, pm_mode_str[val]);

	return scnprintf(buf, PAGE_SIZE - 1, "%d\n", val);
}

static ssize_t dhd_pm_store(struct kobject *kobj, struct kobj_attribute *attr,
                            const char *buf, size_t count)
{
	int val, err;

	if (sscanf(buf, "%d", &val) != 1)
		return -EINVAL;

	err = dhd_wl_ioctl_cmd(p_dhd, WLC_SET_PM, (char *)&val, sizeof(val), TRUE, 0);
	if (err)
		return -EIO;

	return count;
}

static ssize_t dhd_pm_resume_show(struct kobject *kobj, struct kobj_attribute *attr, char *buf)
{
	int val = atomic_read(&dhd_pm_resume);

	if (val <= (ARRAY_SIZE(pm_mode_str) - 1))
		return scnprintf(buf, PAGE_SIZE - 1, "%d: %s\n", val, pm_mode_str[val]);

	return -EINVAL;
}

static ssize_t dhd_pm_resume_store(struct kobject *kobj, struct kobj_attribute *attr,
                                    const char *buf, size_t count)
{
	int val;

	if (sscanf(buf, "%d", &val) != 1)
		return -EINVAL;

	if (val < 0 || val > (ARRAY_SIZE(pm_mode_str) - 1))
		return -EINVAL;

	// XXX: this flag should be atomic actually
	if (p_dhd->in_suspend)
		return -EBUSY;

	atomic_set(&dhd_pm_resume, val);

	return count;
}

static ssize_t dhd_pm_suspend_show(struct kobject *kobj, struct kobj_attribute *attr, char *buf)
{
	int val = atomic_read(&dhd_pm_suspend);

	if (val <= (ARRAY_SIZE(pm_mode_str) - 1))
		return scnprintf(buf, PAGE_SIZE - 1, "%d: %s\n", val, pm_mode_str[val]);

	return -EINVAL;
}

static ssize_t dhd_pm_suspend_store(struct kobject *kobj, struct kobj_attribute *attr,
                                    const char *buf, size_t count)
{
	int val;

	if (sscanf(buf, "%d", &val) != 1)
		return -EINVAL;

	if (val < 0 || val > (ARRAY_SIZE(pm_mode_str) - 1))
		return -EINVAL;

	if (p_dhd->in_suspend)
		return -EBUSY;

	atomic_set(&dhd_pm_suspend, val);

	return count;
}

static ssize_t dhd_pm_no_suspend_show(struct kobject *kobj, struct kobj_attribute *attr, char *buf)
{
	return scnprintf(buf, PAGE_SIZE - 1, "%d\n", p_dhd->suspend_disable_flag);
}

static ssize_t dhd_pm_no_suspend_store(struct kobject *kobj, struct kobj_attribute *attr,
                                        const char *buf, size_t count)
{
	int val;

	if (sscanf(buf, "%d", &val) != 1)
		return -EINVAL;

	if (p_dhd->in_suspend)
		return -EBUSY;

	// XXX: this flag needs to synchronize actually
	p_dhd->suspend_disable_flag = 1;

	return count;
}

static struct kobj_attribute dhd_pm_mode_interface =
	__ATTR(pm_mode, 0644, dhd_pm_show, dhd_pm_store);

static struct kobj_attribute dhd_pm_resume_interface =
	__ATTR(pm_resume, 0644, dhd_pm_resume_show, dhd_pm_resume_store);

static struct kobj_attribute dhd_pm_suspend_interface =
	__ATTR(pm_suspend, 0644, dhd_pm_suspend_show, dhd_pm_suspend_store);

static struct kobj_attribute dhd_pm_no_suspend_interface =
	__ATTR(pm_no_suspend, 0644, dhd_pm_no_suspend_show, dhd_pm_no_suspend_store);

static struct attribute *dhd_pm_sysfs_attrs[] = {
	&dhd_pm_mode_interface.attr,
	&dhd_pm_resume_interface.attr,
	&dhd_pm_suspend_interface.attr,
	&dhd_pm_no_suspend_interface.attr,
	NULL,
};

static struct attribute_group dhd_sysfs_pm_ifgroup = {
	.name  = "pm",
	.attrs = dhd_pm_sysfs_attrs,
};

static ssize_t dhd_band_show(struct kobject *kobj, struct kobj_attribute *attr, char *buf)
{
	dhd_info_t 		*dhd = (dhd_info_t *)p_dhd->info;
	dhd_if_t 		*ifp;
	struct net_device 	*net;
	uint 			band;
	int			err;

	ifp = dhd->iflist[0];
	if (!ifp)
		return -ENODEV;

	net = ifp->net;
	if (!net)
		return -ENODEV;

	if ((err = wldev_get_band(net, &band))) {
		pr_err("%s: wldev_get_band() failed (%d)\n", __func__, err);
		return err;
	}

	if ((band < 0) || (band > ARRAY_SIZE(band_str) - 1))
		return -EINVAL;

	return scnprintf(buf, PAGE_SIZE - 1, "%u: %s\n", band, band_str[band]);
}

static ssize_t dhd_band_store(struct kobject *kobj, struct kobj_attribute *attr,
                                        const char *buf, size_t count)
{
	dhd_info_t 		*dhd = (dhd_info_t *)p_dhd->info;
	dhd_if_t 		*ifp;
	struct net_device 	*net;
	uint			band;
	int			err;

	ifp = dhd->iflist[0];
	if (!ifp)
		return -ENODEV;

	net = ifp->net;
	if (!net)
		return -ENODEV;

	if (sscanf(buf, "%u", &band) != 1)
		return -EINVAL;

	if ((err = wldev_set_band(net, band))) {
		pr_err("%s: wldev_set_band() failed (%d)\n", __func__, err);
		return err;
	}

	return count;
}

static ssize_t dhd_band_cfg80211_show(struct kobject *kobj, struct kobj_attribute *attr, char *buf)
{
	dhd_info_t 		*dhd = (dhd_info_t *)p_dhd->info;
	dhd_if_t 		*ifp;
	struct net_device 	*net;
	// char 			ioctl_buf[32];
	int 			band;
	int			err;

	ifp = dhd->iflist[0];
	if (!ifp)
		return -ENODEV;

	net = ifp->net;
	if (!net)
		return -ENODEV;

	if ((err = wldev_iovar_getint(net, "if_band", &band))) {
		pr_err("%s: wldev_iovar_getint(): %d\n", __func__, err);
		return err;
	}

	if (band > ARRAY_SIZE(band_str) - 1)
		return -EINVAL;

	return scnprintf(buf, PAGE_SIZE - 1, "%u: %s\n", band, band_str[band]);
}

static ssize_t dhd_band_cfg80211_store(struct kobject *kobj, struct kobj_attribute *attr,
                                        const char *buf, size_t count)
{
	dhd_info_t 		*dhd = (dhd_info_t *)p_dhd->info;
	dhd_if_t 		*ifp;
	struct net_device 	*net;
	uint			band;
	int			err;

	ifp = dhd->iflist[0];
	if (!ifp)
		return -ENODEV;

	net = ifp->net;
	if (!net)
		return -ENODEV;

	if (sscanf(buf, "%u", &band) != 1)
		return -EINVAL;

	if ((err = wl_cfg80211_set_if_band(net, band))) {
		pr_err("%s: wl_cfg80211_set_if_band() failed (%d)\n", __func__, err);
		return err;
	}

	return count;
}

static ssize_t dhd_txpower_show(struct kobject *kobj, struct kobj_attribute *attr, char *buf)
{
	dhd_info_t 		*dhd = (dhd_info_t *)p_dhd->info;
	dhd_if_t 		*ifp;
	struct net_device 	*net;
	char			ioctl_buf[WLC_IOCTL_SMLEN];
	int 			qdbm;
	int			err;

	ifp = dhd->iflist[0];
	if (!ifp)
		return -ENODEV;

	net = ifp->net;
	if (!net)
		return -ENODEV;

	err = wldev_iovar_getbuf_bsscfg(net, "qtxpower", NULL, 0,
	                                ioctl_buf, WLC_IOCTL_SMLEN, 0, NULL);
	if (err)
		return err;

	memcpy(&qdbm, ioctl_buf, sizeof(qdbm));
	qdbm = dtoh32(qdbm);

	return scnprintf(buf, PAGE_SIZE - 1, "%s: %d\n",
	                 qdbm & WL_TXPWR_OVERRIDE ? "fixed" : "auto",
	                 (qdbm & ~WL_TXPWR_OVERRIDE) / 4);
}

static ssize_t dhd_txpower_store(struct kobject *kobj, struct kobj_attribute *attr,
                                        const char *buf, size_t count)
{
	dhd_info_t 			*dhd = (dhd_info_t *)p_dhd->info;
	dhd_if_t 			*ifp;
	struct net_device 		*net;
	enum nl80211_tx_power_setting 	type;
	int				dbm;
	int				err;

	ifp = dhd->iflist[0];
	if (!ifp)
		return -ENODEV;

	net = ifp->net;
	if (!net)
		return -ENODEV;

	if (sscanf(buf, "%d", &dbm) != 1)
		return -EINVAL;

	if (dbm == -1)
		type = NL80211_TX_POWER_AUTOMATIC;
	else
		type = NL80211_TX_POWER_FIXED;

	if ((err = wl_set_tx_power(net, type, dbm))) {
		pr_err("%s: wl_set_tx_power() failed (%d)\n", __func__, err);
		return err;
	}

	return count;
}

static ssize_t dhd_linkspeed_show(struct kobject *kobj, struct kobj_attribute *attr, char *buf)
{
	dhd_info_t 		*dhd = (dhd_info_t *)p_dhd->info;
	dhd_if_t 		*ifp;
	struct net_device 	*net;
	int 			linkspeed;
	int			err;

	ifp = dhd->iflist[0];
	if (!ifp)
		return -ENODEV;

	net = ifp->net;
	if (!net)
		return -ENODEV;

	if ((err = wldev_get_link_speed(net, &linkspeed))) {
		pr_err("%s: wldev_get_link_speed(): %d\n", __func__, err);
		return err;
	}

	return scnprintf(buf, PAGE_SIZE - 1, "%d Mbps\n", linkspeed / 1000);
}

static struct kobj_attribute dhd_band_interface =
	__ATTR(band, 0644, dhd_band_show, dhd_band_store);

static struct kobj_attribute dhd_band_cfg80211_interface =
	__ATTR(band_cfg80211, 0644, dhd_band_cfg80211_show, dhd_band_cfg80211_store);

static struct kobj_attribute dhd_txpower_interface =
	__ATTR(tx_power, 0644, dhd_txpower_show, dhd_txpower_store);

static struct kobj_attribute dhd_linkspeed_interface =
	__ATTR(link_speed, 0444, dhd_linkspeed_show, NULL);

static struct attribute *dhd_sysfs_attrs[] = {
	&dhd_band_interface.attr,
	&dhd_band_cfg80211_interface.attr,
	&dhd_txpower_interface.attr,
	&dhd_linkspeed_interface.attr,
	NULL,
};

static struct attribute_group dhd_sysfs_ifgroup = {
	.attrs = dhd_sysfs_attrs,
};

static struct attribute_group *dhd_inteface_groups[] = {
	&dhd_sysfs_ioctl_ifgroup,
	&dhd_sysfs_pm_ifgroup,
	&dhd_sysfs_ifgroup,
	NULL,
};

static struct kobject *dhd_sysfs_kobject;

int bcmdhd_sysfs_init(dhd_pub_t *dhd)
{
	int ret;
	int i;

	mutex_init(&ioctl_mutex);

	dhd_sysfs_kobject = kobject_create_and_add("bcmdhd", kernel_kobj);
	if (!dhd_sysfs_kobject) {
		pr_err("%s: failed to create kobject interface\n", __func__);
		return -EIO;
	}

	for (i = 0; dhd_inteface_groups[i]; i++) {
		ret = sysfs_create_group(dhd_sysfs_kobject, dhd_inteface_groups[i]);
		if (ret) {
			pr_err("%s: failed to create to sysfs attr group\n", __func__);
			goto err;
		}
	}

	p_dhd = dhd;

        return ret;

err:
	kobject_put(dhd_sysfs_kobject);

	return ret;
}

void bcmdhd_sysfs_deinit(void)
{
	if (!p_dhd)
		return;

	mutex_lock(&ioctl_mutex);

	ioctl_buf_free();

	kobject_put(dhd_sysfs_kobject);

	mutex_unlock(&ioctl_mutex);
}
