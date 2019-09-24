#include <unistd.h>
#include <stdio.h>

int main(int argc, char *argv[])
{
    execv("./mqtt_broker", argv);
    return 0;
}
