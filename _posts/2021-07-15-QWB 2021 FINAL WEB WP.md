---
layout:     post
title:      QWB 2021 FINAL WEB WP
subtitle:   QWB 2021 FINAL WEB WP
date:       20210715
author:     murrayalf
header-img: img/the-first.png
catalog: false
tags:
    - writeup
---

前段时间参加了第五届强网杯线下赛，也是我第一次参加线下赛。经历了32个小时的鏖战，感受web题目质量还是很高的，最终勉强只做出来了几道题，和大手子们还是差的很远。现在进行一下做出来的题目的复盘，也还原一下当时的心路历程。

## 一、渗透01-mDMZ

#### 0x01 代理、转发工具

刚发布题目看到是一道渗透题，真是打人一个措手不及，因为之前根本没有准备渗透需要的内容。比赛方给了一个linux的跳板机，登陆后就开始想需要代理或者端口转发的工具，还要准备扫内网找靶机。

提示说靶机是在10.0.0.0/24内，一开始就ping到了10.0.0.1和10.0.0.2两台机器，就开始找代理和转发工具，因为以前用过frp，就用frp把10.0.0.1/2的80，443都转出来，可能是第一次哪一步弄错了，没发现这两台主机开了web服务，于是就怀疑是不是还有别的机器。就又写了一个脚本去ping整个C段，跑脚本的同时去找socks5代理工具。等脚本跑完了，发现整个C段只有这两台主机可以ping通。socks5代理工具也找到了狗洞，测试的过程也吃了亏，开始用windows主机测试，使用proxifier代理本地端口，一直ping不通10.0.0.1（现在也不知道到底是怎么回事）。后来使用kali proxychain就能成功ping通10.0.0.1，访问了一下10.0.0.2:80就发现了目标网站。惊讶的我又重新配置了一遍frp，结果又能成功访问了。这时候已经十点半了，我们才开始做题- -

#### 0x02 yzncms

简单扫了一下发现www.zip存在源码泄露，是一个php CMS yzncms。点了点功能发现都返回404，后来才发现路径还需要index.php，要在index.php/后添加内容才可以正常访问，后台地址在admin上，简单试了一下admin:admin，可以登录。点一点各个功能点，就准备部署到本地开始源码审计了。

先部署了一下数据库，然后把项目拖到phpstudy就可以访问public/index.php了。查阅了一下yzncms的相关资料，发现是基于thinkphp5的CMS框架，大概了解其MVC框架，目录结构。下载了公开的最新的yzncms项目源码，winmerge之后发现本来存在漏洞点的地方都被补了，就只能找新洞了。通过对比发现

yzncms/addons/loginbg/Loginbg.php有明显不同，而且存在漏洞风险，$config['pic']如果是可控的话，11行即可以任意文件读取，结合上传文件还可以触发phar反序列化漏洞。18、19行还可能存在模板注入漏洞

```php
 public function adminLoginStyle()
 {
     $config = $this->getAddonConfig();
     if ($config['mode'] == 'random' || $config['mode'] == 'daily') {
         $gettime     = $config['mode'] == 'random' ? mt_rand(-1, 7) : 0;
         $json_string = file_get_contents('https://www.bing.com/HPImageArchive.aspx?format=js&idx=' . $gettime . '&n=1');
         $data        = json_decode($json_string);
         $background  = "https://www.bing.com" . $data->{"images"}[0]->{"urlbase"} . "_1920x1080.jpg";
     } else {
         if ($config['load'] == 'embed' && (file_exists($config['pic']) || stristr($config['pic'], 'http://') || stristr($config['pic'], 'https://'))) {
             $background = 'data:image/png;base64,'.base64_encode(@file_get_contents($config['pic']));
         } 
         else {
             $background = $config['pic'];
         }
     }

     $this->assign('background', $background);
     return $this->fetch('loginbg');
 }
```

通过进一步burp抓包测试，发现yzncms/application/addons/controller/Addons.php config函数负责处理对插件的更改，而且对LoginBp插件的Config['pic']没有任何过滤。

```php
/**
 * 设置插件页面
 */
public function config($name = null)
{
    $name = $name ? $name : $this->request->get("name");
    if (!$name) {
        $this->error('参数不得为空！');
    }
    if (!preg_match('/^[a-zA-Z0-9]+$/', $name)) {
        $this->error('插件名称不正确！');
    }
    if (!is_dir(ADDON_PATH . $name)) {
        $this->error('目录不存在！');
    }
    $info   = get_addon_info($name);
    $config = get_addon_fullconfig($name);
    if (!$info) {
        $this->error('配置不存在！');
    }
    if ($this->request->isPost()) {
        $params = $this->request->post("config/a", [], 'trim');
        if ($params) {
            foreach ($config as $k => &$v) {
                if (isset($params[$v['name']])) {
                    if ($v['type'] == 'array') {
                        $params[$v['name']] = is_array($params[$v['name']]) ? $params[$v['name']] : (array) json_decode($params[$v['name']],
                                                                                                                        true);
                        $value = $params[$v['name']];
                    } else {
                        $value = is_array($params[$v['name']]) ? implode(',',
                                                                         $params[$v['name']]) : $params[$v['name']];
                    }
                    $v['value'] = $value;
                }
            }
            try {
                //更新配置文件
                set_addon_fullconfig($name, $config);
                //AddonService::refresh();
            } catch (\Exception $e) {
                $this->error($e->getMessage());
            }
        }
        $this->success('插件配置成功！');
    }
    $this->assign('data', ['info' => $info, 'config' => $config]);
    $configFile = ADDON_PATH . $name . DS . 'config.html';
    if (is_file($configFile)) {
        $this->assign('custom_config', $this->view->fetch($configFile));
    }
    return $this->fetch();
}
```

参数处理过程大概是在后台插件管理->后台登录背景插件->上传图片，提交修改->截包并修改config[pic]参数

![1626250657375](img-post/1626250657375.png)

然后打开yzncms\addons\loginbg\config.php，会发现pic部分的value已经被改变

```php
 2 => 
  array (
    'name' => 'pic',
    'title' => '固定图片',
    'type' => 'image',
    'value' => 'configtest',
    'tip' => '选择固定则需要上传此图片',
  ),
```

接着再退出用户，重新登录admin页面的时候则会调用yzncms/addons/loginbg/Loginbg.php adminLoginStyle漏洞函数并进行模板渲染，可以看到之前上传的内容已经被渲染进了模板。

![162345](img-post/162345.png)

接下来就可以通过修改config[load]和config[pic]的值来进行任意文件读取，比如读/flag

进一步利用可以构造thinkphp5反序列化RCE的phar，修改文件后缀上传，再通过这个点利用达成getshell

这道题我就只做到了这个程度，没做出来第二步有点可惜，都看不到第三步的题目。



## 二、OA

源码包是信呼，免费开源的办公OA系统，在readme文件中可以看到版本整理时间：2021-03-05 23:59:59  
版本号：V2.2.2  通过查阅资料发现最新版本已经到2.2.7

还是先部署数据库，再拖到phpstudy就可以使用了

该题目存在数据库的admin密码甚至不是32位，但是登陆时需要比较传入的password的MD5值和数据库中的密码，所以该题无法使用admin登录，但是可以使用test用户登录，并且对MD5进行解密发现是abc123

后台有很多上传点，但是对文件后缀有严格的过滤oa/include/chajian/upfileChajian.php

```php
/**
    上传
    @param	$name	string	对应文本框名称
    @param	$cfile	string	文件名心的文件名，不带扩展名的
    @return	string/array
*/
public function up($name,$cfile='')
{
    if(!$_FILES)return 'sorry!';
    $file_name		= $_FILES[$name]['name'];
    $file_size		= $_FILES[$name]['size'];//字节
    $file_type		= $_FILES[$name]['type'];
    $file_error		= $_FILES[$name]['error'];
    $file_tmp_name	= $_FILES[$name]['tmp_name'];
    $zongmax		= $this->getmaxupsize();	
    if($file_size<=0 || $file_size > $zongmax){
        return '文件为0字节/超过'.$this->formatsize($zongmax).'，不能上传';
    }
    $file_sizecn	= $this->formatsize($file_size);
    $file_ext		= $this->getext($file_name);//文件扩展名

    $file_img		= $this->isimg($file_ext);
    $file_kup		= $this->issavefile($file_ext);
    
    if(!$file_img && !$this->isoffice($file_ext) && getconfig('systype')=='demo')return '演示站点禁止文件上传';
    
    if($file_error>0){
        $rrs = $this->geterrmsg($file_error);
        return $rrs;
    }
        
    if(!$this->contain('|'.$this->ext.'|', '|'.$file_ext.'|') && $this->ext != '*'){
        return '禁止上传文件类型['.$file_ext.']';
    }
    
    if($file_size>$this->maxsize*1024*1024){
        return '上传文件过大，限制在：'.$this->formatsize($this->maxsize*1024*1024).'内，当前文件大小是：'.$file_sizecn.'';
    }
    
    //创建目录
    $zpath=explode('|',$this->path);
    $mkdir='';
    for($i=0;$i<count($zpath);$i++){
        $mkdir.=''.$zpath[$i].'/';
        if(!is_dir($mkdir))mkdir($mkdir);
    }
    
    //新的文件名
    $file_newname	= $file_name;
    $randname		= $file_name;
    if(!$cfile==''){
        $file_newname=''.$cfile.'.'.$file_ext.'';
    }else{
        $_oldval 	 = m('option')->getval('randfilename');
        $randname	 = $this->getrandfile(1, $_oldval);
        m('option')->setval('randfilename', $randname);
        $file_newname=''.$randname.'.'.$file_ext.'';
    }
    
    $save_path	= ''.str_replace('|','/',$this->path);
    //if(!is_writable($save_path))return '目录'.$save_path.'无法写入不能上传';
    $allfilename= $save_path.'/'.$file_newname.'';
    $uptempname	= $save_path.'/'.$randname.'.uptemp';

    $upbool	 	= true;
    if(!$file_kup){
        $allfilename= $this->filesave($file_tmp_name, $file_newname, $save_path, $file_ext);
        if(isempt($allfilename))return '无法保存到'.$save_path.'';
    }else{
        $upbool		= @move_uploaded_file($file_tmp_name,$allfilename);
    }
    
    if($upbool){
        $picw=0;$pich=0;
        if($file_img){
            $fobj = $this->isimgsave($file_ext, $allfilename);
            if(!$fobj){
                return 'error:非法图片文件';
            }else{
                $picw = $fobj[0];
                $pich = $fobj[1];	
            }
        }
        return array(
            'newfilename' => $file_newname,
            'oldfilename' => $file_name,
            'filesize'    => $file_size,
            'filesizecn'  => $file_sizecn,
            'filetype'    => $file_type,
            'filepath'    => $save_path,
            'fileext'     => $file_ext,
            'allfilename' => $allfilename,
            'picw'        => $picw,
            'pich'        => $pich
        );
    }else{
        return '上传失败：'.$this->geterrmsg($file_error).'';
    }
}
```

23行`$file_kup = $this->issavefile($file_ext);`判断是否是合法的后缀，允许的后缀存在类的声明中：

```php
//可上传文件类型，也就是不保存为uptemp的文件
private $upallfile    = '|doc|docx|xls|xlsx|ppt|pptx|pdf|swf|rar|zip|txt|gz|wav|mp3|avi|mp4|flv|wma|chm|apk|amr|log|json|cdr|';
```

67行` $allfilename= $this->filesave($file_tmp_name, $file_newname, $save_path, $file_ext);`不允许的后缀都会更改后缀，保存为.uptemp文件

include/chajian/upfileChajian.php

```php
public function filesave($oldfile, $filename, $savepath, $ext)
{
    $file_kup	= $this->issavefile($ext);
    $ldisn 		= strrpos($filename, '.');
    if($ldisn>0)$filename = substr($filename, 0, $ldisn);
    $filepath 	= ''.$savepath.'/'.$filename.'.'.$ext.'';
    if(!$file_kup){
        $filebase64	= base64_encode(file_get_contents($oldfile));
        $filepath 	= ''.$savepath.'/'.$filename.'.uptemp';
        $bo 		= $this->rock->createtxt($filepath, $filebase64);
        @unlink($oldfile);
        if(!$bo)$filepath = '';
    }else{
    }
    return $filepath;
}
```

观察数据库可以发现，每一次上传文件都会保存上传文件的原文件名，现文件路径，并且在主页时会调用数据库的内容显示原文件名。

经过搜查公开资料学习到信呼的文件目录和代码框架，审计到`oa/webmain/task/runt/qcloudCosAction.php`中runAction函数会改变文件后缀为原名称。那么就可以通过上传php文件，生成uptemp文件，再通过runAction修改后缀即可以直接getshell。

```php
/**
*  发送上传文件
*  php task.php qcloudCos,run -fileid=1
*  http://你地址/task.php?m=qcloudCos|runt&a=run&fileid=文件id
*/
public function runAction()
{
    $fileid = (int)$this->getparams('fileid','0'); //文件ID
    if($fileid<=0)return 'error fileid';
    $frs 	= m('file')->getone($fileid);
    if(!$frs)return 'filers not found';
    
    $filepath 	= $frs['filepath'];
    if(substr($filepath, 0, 4)=='http')return 'filepath is httppath';
    
    if(substr($filepath,-6)=='uptemp'){
        $aupath = ROOT_PATH.'/'.$filepath;
        $nfilepath  = str_replace('.uptemp','.'.$frs['fileext'].'', $filepath);
        $content	= file_get_contents($aupath);
        $this->rock->createtxt($nfilepath, base64_decode($content));
        unlink($aupath);
        $filepath 	= $nfilepath;
    }
    
    $msg 	= $this->sendpath($filepath, $frs, 'filepathout');
    if($msg)return $msg;
    
    $thumbpath	= $frs['thumbpath'];
    if(!isempt($thumbpath)){
        $msg 	= $this->sendpath($thumbpath, $frs, 'thumbplat');
        if($msg)return $msg;
    }
    return 'success';
}
```



## 三、Rua

题目p.php执行phpinfo，file.php支持文件读取，利用file.php读file.php

```php
<?php
if(stripos($_GET['file'], "gopher") !== FALSE)
    die("no gopher, try to find another ssrf on this server!");
else
    echo file_get_contents($_GET['file']);
```

根据phpinfo allow_url_fopen=On，再结合gopher和file_get_contents，利用file_get_contents读/flag了解到这道题是考察ssrf

根据phpinfo获取网站目录，nginx配置目录并读取

1. 读/etc/hosts 得到内网ip和网段

```
127.0.0.1	localhost
::1	localhost ip6-localhost ip6-loopback
fe00::0	ip6-localnet
ff00::0	ip6-mcastprefix
ff02::1	ip6-allnodes
ff02::2	ip6-allrouters
172.18.0.2	ae0ad8408c36
```

2. nginx.conf 了解有http服务

```
user  root;
worker_processes  1;

#error_log  logs/error.log;
#error_log  logs/error.log  notice;
#error_log  logs/error.log  info;

#pid        logs/nginx.pid;


events {
    worker_connections  1024;
}


http {
    include       mime.types;
    default_type  application/octet-stream;

    #log_format  main  '$remote_addr - $remote_user [$time_local] "$request" '
    #                  '$status $body_bytes_sent "$http_referer" '
    #                  '"$http_user_agent" "$http_x_forwarded_for"';

    #access_log  logs/access.log  main;

    sendfile        on;
    #tcp_nopush     on;

    #keepalive_timeout  0;
    keepalive_timeout  65;

    #gzip  on;

    include /etc/nginx/conf.d/*.conf;
}
```

3.default.conf 

这个文件很关键，尤其是46行 /api的路由，指示了题目下一步的方向

```
lua_package_path '/usr/local/openresty/lualib/resty/?.ljbc;;';

lua_ssl_verify_depth 2;
lua_ssl_trusted_certificate '/etc/ssl/certs/ca-certificates.crt';

log_format  main  '$remote_addr - $remote_user [$time_local] "$request" '
                    '$status $body_bytes_sent ';

server {
    listen       80;
    server_name  localhost;

    access_log  /usr/local/openresty/nginx/logs/access.log  main;
    access_log  /usr/local/openresty/nginx/logs/access2.log  main;

    location / {
        root   /usr/local/openresty/nginx/html;
        index  index.html index.htm index.php;
        try_files $uri $uri/ /index.php?$query_string;
    }

    #error_page  404              /404.html;

    # redirect server error pages to the static page /50x.html
    #
    error_page   500 502 503 504  /50x.html;
    location = /50x.html {
        root   /usr/local/openresty/nginx/html;
    }

    # proxy the PHP scripts to Apache listening on 127.0.0.1:80
    #
    #location ~ \.php$ {
    #    proxy_pass   http://127.0.0.1;
    #}

    # pass the PHP scripts to FastCGI server listening on 127.0.0.1:9000
    #
    location ~ \.php$ {
            fastcgi_pass   unix:/dev/shm/php-cgi.sock;
            fastcgi_index  index.php;
            fastcgi_param  SCRIPT_FILENAME  $document_root$fastcgi_script_name;
            include        fastcgi_params;
    }

    location /api {      
        default_type text/html;
        content_by_lua_block {
            local httpd = require "resty.http_dns"  
            ngx.req.read_body()  
            local args = ngx.req.get_uri_args()
            local headers = ngx.req.get_headers()
	    local post_data = ngx.req.get_body_data() 
            local url = args.url                    
            
			local domain = ngx.re.match(url, [[//([\S]+?)/]])     
            domain = (domain and 1 == #domain and domain[1]) or nil            

            if domain == "sisselcbp.github.io" then     
                local res = httpd:http_request_with_dns(url,{})   
                ngx.print(res.body)
            elseif domain == "r3kapig.com" then
                local res = httpd:http_request_with_dns(url,{
                    method = "POST",
                    body = post_data,
                    headers = {
                        ["Content-Type"] = headers["Content-Type"]
                    }
                })                
                ngx.print(res.body)   
            else         
                ngx.print("Error! Try it local to read the log!") 
            end    
        }
    }

    # deny access to .htaccess files, if Apache's document root
    # concurs with nginx's one
    #
    #location ~ /\.ht {
    #    deny  all;
    #}
}
```

不难看出该服务是由lua语言写的，

49行`local httpd = require "resty.http_dns"  ` 在github上lua-resty-http能找到部分源码

在http://moguhu.com/article/detail?articleId=82可以找到http_dns.lua源码

```lua
local http = require "resty.http"
local resolver = require "resty.dns.resolver"

local _M = {}

_M._VERSION="0.1"

function _M:http_request_with_dns( url, param )
    -- get domain
    local domain = ngx.re.match(url, [[//([\S]+?)/]])
    domain = (domain and 1 == #domain and domain[1]) or nil
    if not domain then
        ngx.log(ngx.ERR, "get the domain fail from url:", url)
        return {status=ngx.HTTP_BAD_REQUEST}
    end

    -- add param
    if not param.headers then
        param.headers = {}
    end
    param.headers.Host = domain

    -- get domain ip
    local domain_ip, err = self:get_domain_ip_by_dns(domain)
    if not domain_ip then
        ngx.log(ngx.ERR, "get the domain[", domain ,"] ip by dns failed:", err)
        return {status=ngx.HTTP_SERVICE_UNAVAILABLE}
    end

    -- http request
    local httpc = http.new()
    local temp_url = ngx.re.gsub(url, "//"..domain.."/", string.format("//%s/", domain_ip))

    local res, err = httpc:request_uri(temp_url, param)
    if err then
        return {status=ngx.HTTP_SERVICE_UNAVAILABLE}
    end

    -- httpc:request_uri 内部已经调用了keepalive，默认支持长连接
    -- httpc:set_keepalive(1000, 100)
    return res
end


-- 根据域名获取IP地址
function _M:get_domain_ip_by_dns( domain )
  -- 这里写死了google的域名服务ip，要根据实际情况做调整（例如放到指定配置或数据库中）
  local dns = "8.8.8.8"

  local r, err = resolver:new{
      nameservers = {dns, {dns, 53} },
      retrans = 5,  -- 5 retransmissions on receive timeout
      timeout = 2000,  -- 2 sec
  }

  if not r then
      return nil, "failed to instantiate the resolver: " .. err
  end

  local answers, err = r:query(domain)
  if not answers then
      return nil, "failed to query the DNS server: " .. err
  end

  if answers.errcode then
      return nil, "server returned error code: " .. answers.errcode .. ": " .. answers.errstr
  end

  for i, ans in ipairs(answers) do
    if ans.address then
      return ans.address
    end
  end

  return nil, "not founded"
end

return _M
```

继续分析/api路由的处理逻辑:

```lua
location /api {      
    default_type text/html;
    content_by_lua_block {
        local httpd = require "resty.http_dns"  
        ngx.req.read_body()  
        local args = ngx.req.get_uri_args()
        local headers = ngx.req.get_headers()
        local post_data = ngx.req.get_body_data() 
        local url = args.url
        local domain = ngx.re.match(url, [[//([\S]+?)/]])         
        domain = (domain and 1 == #domain and domain[1]) or nil           
        if domain == "sisselcbp.github.io" then     
            local res = httpd:http_request_with_dns(url,{})       
            ngx.print(res.body)
        elseif domain == "r3kapig.com" then
            local res = httpd:http_request_with_dns(url,{
                    method = "POST",
                    body = post_data,
                    headers = {
                        ["Content-Type"] = headers["Content-Type"]
                    }
                })                
            ngx.print(res.body)   
        else         
            ngx.print("Error! Try it local to read the log!") 
        end    
    }
```

可以看出先获取url中的url参数赋值url变量，经过正则处理后赋值domain变量，经过比对后http_request_with_dns访问url，这里存在一个针对正则的绕过，给出payload：

```
\api?url=http://127.0.0.1:80 //sisselcbp.github.io/
```

即可绕过[[//([\S]+?)/]]（非空连续字符）对127.0.0.1:80的匹配，使得domain赋值成功的情况下可控实际访问的url。

接着找到内网靶机修改domain为r3kapig.com，按要求发送post包即可get flag
