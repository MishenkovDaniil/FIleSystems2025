# FAT 16

Написать программу, которая для системы FAT16
- Распечатывает список файлов в корневом каталоге,
- Напротив каждого пишет атрибуты и время создания/изменения,
- Читает файл, сохранённый в образе FAT16, и печатает его в stdout.


## Пререквизиты

### Создание образа

``` bash
#!/bin/bash
dd if=/dev/zero of=disk.img bs=1M count=2
mkfs.fat -F 16 disk.img
```

### Редактирование образа (добавление файлов)

``` bash
#!/bin/bash
sudo mount -o loop disk.img /mnt

# adding/changing files in our fs through /mnt

sudo umount /mnt
```
