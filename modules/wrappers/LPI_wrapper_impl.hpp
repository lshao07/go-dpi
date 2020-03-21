#include <stdint.h>
typedef void lpi_data_t;

struct lpiResult {
	uint32_t proto;
	uint32_t category;
};

#ifdef __cplusplus
extern "C" {
#endif
int lpiInitLibrary();
lpi_data_t *lpiCreateFlow();
void lpiFreeFlow(lpi_data_t*);
int lpiAddPacketToFlow(lpi_data_t*, const void*, unsigned short);
struct lpiResult *lpiGuessProtocol(lpi_data_t*);
void lpiDestroyLibrary();
#ifdef __cplusplus
}
#endif
