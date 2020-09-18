# DBG Utils for GDB

## 安装

### Python 
```sh
python -m pip install dbg_utils
# try "sudo python setup.py install" when fail
```


### IDA

复制 `idp.py` 到 `[IDA INSTALL PATH]/plugins/idp.py` 



## 使用


### 服务端

```sh
systemctl start idpss
```

### IDA

- 配置

```python
idp_config(server_ip, server_port)
```

- 同步 断点、变量

**Ctrl-Alt-D** 
