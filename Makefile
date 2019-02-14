#
# $FreeBSD: releng/12.0/usr.sbin/bhyve/Makefile 339949 2018-10-31 12:05:45Z bz $
#

CFLAGS+=-I${SRCTOP}/sys

PROG=	bhyve-mini
PACKAGE=	bhyve-mini

DEBUG_FLAGS= -g -O0

MAN=	bhyve-mini.8

BHYVE_SYSDIR?=${SRCTOP}

SRCS=	\
	acpi.c			\
	bhyverun.c		\
	block_if.c		\
	bootrom.c		\
	fwctl.c			\
	inout.c			\
	ioapic.c		\
	kexec.c			\
	mem.c			\
	mevent.c		\
	mptbl.c			\
	pci_emul.c		\
	pci_hostbridge.c	\
	pci_irq.c		\
	pci_lpc.c		\
	pci_nvme.c		\
	pci_passthru.c		\
	pci_virtio_block.c	\
	pci_virtio_console.c	\
	pci_virtio_net.c	\
	pci_virtio_rnd.c	\
	pci_uart.c		\
	pm.c			\
	post.c			\
	rtc.c			\
	smbiostbl.c		\
	sockstream.c		\
	task_switch.c		\
	uart_emul.c		\
	virtio.c		\
	xmsr.c			\
	spinup_ap.c		\
	iov.c

.PATH:  ${BHYVE_SYSDIR}/sys/amd64/vmm
SRCS+=	vmm_instruction_emul.c

LDADD=	-lvmmapi -lmd -lpthread -lz -lutil -lsbuf

CFLAGS+=-DINET
CFLAGS+=-DINET6
LDADD+=	-lcrypto

WARNS?=	2

.include <bsd.prog.mk>
