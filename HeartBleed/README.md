## HeartBleed攻击重放案例

### 攻击记录过程：
HeartBleedServer.qcow2镜像的云盘地址：

```
https://pan.baidu.com/s/1pvErxQFB39Eulbtm1r32Mw        提取码：lv6g
```

1. 在服务器中启动虚拟机：

   ```shell
panda@hust:~/build-panda/x86_64-softmmu$ sudo ./qemu-system-x86_64 -m 2048M /home/panda/images/HeartBleedServer.qcow2 --monitor stdio -net user,hostfwd=tcp::443-:443 -net nic -usbdevice tablet -vnc :8
   ```

2. 在攻击机hosts文件中添加一下域名信息，222.20.79.157为运行panda的服务器的地址，在攻击机中访问网址www.heartbleedtestofpanda.com进行登录操作，管理员的用户名admin 密码seedelgg：

   ```
   222.20.79.157 www.heartbleedtestofpanda.com
   ```

3. 在服务器的qemu的monitor中开启记录：

   ```
   (qemu) begin_record HeartBleed
   ```

4. 在攻击机上用ssltest.py脚本进行多次攻击，环境为python2.7：

   ```shell
   ssltest.py www.heartbleedtestofpanda.com > hb_attack.log
   ```

5. 攻击完成后，在服务器的qemu的monitor中结束记录：

   ```
   (qemu) end_record
   ```

记录的Heartbleed日志文件的网盘地址：

```
https://pan.baidu.com/s/1HYe5hHjLBsdSEpD5tbv2Qw  提取码：dt08
```

### 攻击重放分析过程：

1. 新建文本文档，将要分析敏感字符串放入其中用双引号包裹""，每行一个：

   ```shell
   panda@hust:~/build-panda/x86_64-softmmu$ touch keyword_search_strings.txt
   panda@hust:~/build-panda/x86_64-softmmu$ echo "\"seedelgg\"" > keyword_search_strings.txt
   panda@hust:~/build-panda/x86_64-softmmu$ cat keyword_search_strings.txt
   "seedelgg"
   ```

2. 重放分析命令：
   ```shell
   panda@hust:~/build-panda/x86_64-softmmu$ sudo ./qemu-system-x86_64 -m 2048M -usbdevice tablet -replay HeartBleed -os linux-32-ubuntu:3.5.0-37-generic  -panda stringsearch:name=keyword -panda tstringsearch -panda tainted_net:query_outgoing_network=true,file=keyword_tainted.csv -panda jsonlog
   ```

最终生成的文件有：

* 关键字匹配的日志：keyword_string_matches.txt 

* 污点传出网络的日志：keyword_tainted.csv 

* 格式化的json日志：jsonlog.json 