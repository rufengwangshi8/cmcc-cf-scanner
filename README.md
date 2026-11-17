# 移动优选扫描（CMIN2 专用）

一个安卓 App，帮中国移动家庭宽带用户从 Cloudflare 官方 IP 里找出走**特殊线路（CMIN2 精品网）**的候选 IP，并测出下载速度。

一般的优选 App 只看延迟，延迟低的 IP 不一定走 CMIN2，在移动线上常常不能用。这个 App 先认线路，再测速度。

## 它怎么判断特殊线路

1. 先通过 `speed.cloudflare.com/cdn-cgi/trace` 确认当前网络的基准出口 IP。
2. 直连每一个候选 Cloudflare IP 的 443 端口（SNI 为 `speed.cloudflare.com`），再取一次 trace。
3. 如果这次看到的出口 IP 和基准不一样，说明这个 IP 走了不同的线路，就是特殊线路候选。
4. 对候选 IP 做 10 秒下载测速，按下载速度从高到低排序。

## 怎么装

到本仓库的 [Releases](../../releases) 页，下载 `apk-latest` 里面的 `app-debug.apk`，在手机上安装。

也可以在 [Actions](../../actions) 里找到最近一次构建，在 Artifacts 处下载 `app-debug`。

## 怎么用

1. 手机连接家里 WiFi（中国移动家庭宽带），并关闭代理软件。
2. 打开 App，点**开始扫描**。
3. 扫完后列表按下载速度排序，点任意一行复制这个 IP，点**复制全部**可以一次复制所有 IP。
4. 把 IP 放进汇聚订阅，在 FlClash 里更新后测速使用。

注意：

- 只能在移动家庭宽带上用，手机流量不行。
- 优选 IP 每隔几天会变，要定期重扫。
- 扫描数量默认 2000，数量越大扫得越全、也越慢。

## 隐私

不上传任何数据，不需要账号，没有广告。所有扫描都在你自己的手机和你自己的网络上完成。

## 自己编译

用 Android Studio 打开本项目，点 Run；或在命令行执行：

```
gradle assembleDebug
```

生成的 APK 在 `app/build/outputs/apk/debug/app-debug.apk`。

## 思路来源

- [CloudFlareScan](https://github.com/xiaolin-007/CloudFlareScan)：从 Cloudflare 官方网段生成候选 IP 并测速。
- `cmcc_cf_special_route_scan.py`：用出口 IP 对比识别移动特殊线路。

## 开源协议

MIT License，见 [LICENSE](LICENSE)。
