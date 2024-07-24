/* setuid program for benchmarking to clear cache.
 * Need to:
 *     chown to root
 *     chmod 4755 to setuid bit
 */
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

main()
{
	int result;

	result = setuid(0);
	system("echo 4 >/proc/sys/vm/drop_caches");
	system("echo 3 >/proc/sys/vm/drop_caches");
}

