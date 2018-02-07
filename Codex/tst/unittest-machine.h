/* vi: set ts=4 expandtab shiftwidth=4: */
#ifndef _H_COM_DIAG_CODEX_UNITTEST_MACHINE_
#define _H_COM_DIAG_CODEX_UNITTEST_MACHINE_

/**
 * @file
 *
 * Copyright 2018 Digital Aggregates Corporation, Colorado, USA<BR>
 * Licensed under the terms in LICENSE.txt<BR>
 * Chip Overclock <coverclock@diag.com><BR>
 * https://github.com/coverclock/com-diag-codex<BR>
 */

typedef enum CodexIndication {
	CODEX_INDICATION_DONE		= -3,	/* Tell FE action complete. */
	CODEX_INDICATION_READY		= -2,	/* Tell NE that FE ready for action. */
	CODEX_INDICATION_FAREND		= -1,	/* Tell FE to prepare for action. */
	CODEX_INDICATION_NONE		=  0,	/* No action in progress. */
	CODEX_INDICATION_NEAREND	=  1,	/* NE readying for action. */
} codex_indication_t;

#endif /* _H_COM_DIAG_CODEX_UNITTEST_MACHINE_ */
