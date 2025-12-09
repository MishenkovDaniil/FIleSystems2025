# каталог-источник
sudo rm -rf /tmp/source_demo
mkdir -p /tmp/source_demo

# тестовая программа (печатает uid/gid/root и ждёт)
cat > /tmp/source_demo/test.c <<'EOF'
#include <stdio.h>
#include <unistd.h>
#include <sys/types.h>
int main(void)
{
    printf("Hello from inside chroot. uid=%d gid=%d pid=%d\n", (int)getuid(), (int)getgid(), (int)getpid());
    fflush(stdout);
    sleep(60); // держим процесс живым минуту для тестов
    return 0;
}
EOF

# demo
gcc -static -O2 -o /tmp/source_demo/test /tmp/source_demo/test.c
chmod 755 /tmp/source_demo/test

sudo ./bind_mount --user nobody --source /tmp/source_demo -- /test