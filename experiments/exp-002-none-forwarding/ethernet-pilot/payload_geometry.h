#ifndef EXP002_PAYLOAD_GEOMETRY_H
#define EXP002_PAYLOAD_GEOMETRY_H
/* Opt-in diagnostic geometry; historical default and storage maxima unchanged. */
#ifndef EP_EXPERIMENT_PAYLOAD
#define EP_EXPERIMENT_PAYLOAD 1024
#endif
#if EP_EXPERIMENT_PAYLOAD != 256 && EP_EXPERIMENT_PAYLOAD != 512 && EP_EXPERIMENT_PAYLOAD != 1024
#error Unsupported diagnostic payload
#endif
#define EG_PAYLOAD EP_EXPERIMENT_PAYLOAD
#define EG_ANNEX (EG_PAYLOAD+14)
#define EG_INPUT (EG_PAYLOAD+108)
#define EG_OUTPUT (EG_PAYLOAD+66)
#define EG_REQUEST (EG_PAYLOAD+144)
#define EG_FRAME (EG_PAYLOAD+80)
#define EG_INGRESS (EG_PAYLOAD+122)
#define EG_SUFFIX (EG_PAYLOAD+56)
#endif
