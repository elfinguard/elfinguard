#include <stdint.h>

#define RETRY_LIMIT 100

#define DRNG_SUCCESS 1
#define DRNG_NOT_READY -1

#if defined(__arm__) || defined(__aarch32__) || defined(__arm64__) || defined(__aarch64__) || defined(_M_ARM)

#define __ARM_FEATURE_RNG
#include <arm_acle.h>

int rdrand_16(uint16_t* x, int retry)
{
	uint64_t r;
	if (retry)
	{
		for (int i = 0; i < RETRY_LIMIT; i++)
		{
			if (__rndr(&r)==0) {
				*x = (uint16_t)r;
				return DRNG_SUCCESS;
			}
		}

		return DRNG_NOT_READY;
	}
	else
	{
			if (__rndr(&r)==0) {
				*x = (uint16_t)r;
				return DRNG_SUCCESS;
			} else
				return DRNG_NOT_READY;
	}
}


#else

#define _rdrand_step(x) ({ unsigned char err; asm volatile("rdrand %0; setc %1":"=r"(*x), "=qm"(err)); err; })

#define _rdrand16_step(x) _rdrand_step(x)

int rdrand_16(uint16_t* x, int retry)
{
	unsigned int i;
		if (retry)
		{
			for (i = 0; i < RETRY_LIMIT; i++)
			{
				if (_rdrand16_step(x))
					return DRNG_SUCCESS;
			}

			return DRNG_NOT_READY;
		}
		else
		{
				if (_rdrand16_step(x))
					return DRNG_SUCCESS;
				else
					return DRNG_NOT_READY;
		}
}

#endif
