# risk
>  框架中的全局风险事件组件


## 内置方法
- [vela.risk() 或者 vela.risk{}](#新建事件)&emsp;新建事件
- [vela.risk.ticker{name}](#事件触发器)&emsp;事件触发器

## 类型常量
- vela.risk.TBrute
- vela.risk.TVirus
- vela.risk.TWeakPass
- vela.risk.TCrawler
- vela.risk.THoneyPot
- vela.risk.TWeb
- vela.risk.TLogin
- vela.risk.TMonitor

## 特定事件函数
> [event](#风险事件) = vela.risk.*{} or [event](#风险事件) = vela.risk.*()
- [brute](#)
- [virus](#)
- [weak_pass](#)
- [crawler](#)
- [web](#)
- [login](#)
- [honey_pot](#)
- [monitor](#)

如下样例:
```lua
    local ev = vela.risk.brute{
        --字段 
    }
    ev.subject = "aaa"
    --todo
```

## 新建事件
> [event](#风险事件) = vela.risk(class , {}) or [event](#风险事件) = vela.risk(class , [string])  <br />
> class:事件类型

```lua
    local ev = vela.risk(vela.risk.TBrute , {
      remote_ip   = "1.1.1.1",
      remote_port = 3654,
      reference   = "https://www.baidu.com",
      payload     = f("user:%s pass:%s" , "admin" , "user"),
      subject     = f("mysql暴力破解事件"),
      alert       = true,
    })

    ev.send()
```

## 事件触发器
> tk = vela.risk.ticker(string) or tk = vela.risk.ticker{name} <br />
> 新建一个触发器, 注意设置触发器的case

内置方法:
- [tk.level(string)](#)&emsp;设置触发条件后的事件等级
- [tk.class(string)](#)&emsp;设置触发条件后的类型
- [tk.db(string)](#)&emsp;计数器存储位置
- [tk.by(string)](#)&emsp;通过[event](#风险事件)维度统计数据;**注意:触发后产生的IP地址信息 首先会从这里的维度获取 其次是[cookie](#cookie)**
- [tk.pay(string, max)](#)&emsp;每个事件的留存数据,采用的是${}取[cookie](#cookie)字段,max:是最多字节数
- [tk.case(cnd)](#);根据[cookie](#cookie)中的值判断是否触发,动作:drop,alert
- [tk.drop](#) &emsp;删除这条统计
- [tk.alert](#) &emsp;告警这条日志
- [tk.hook({id , cookie} , [event](#风险事件))](#) &emsp;每条消息都进行拦截器计算
- [tk.start()](#)
- [tk.push([event](#event))](#)&emsp;写入事件计入统计周期
- [[cookie](#cookie) = tk.event([event](#event))](#)&emsp;写入事件计入统计周期;并返回cookie信息, 注意这里要手动调用cookie.save()

```lua
    local tk  = vela.risk.ticker("ticker")
    tk.level("高危")
    tk.class(vela.risk.TBrute)
    tk.db("honey_pot")
    tk.by("local_ip,remote_ip")
    tk.pay("${remote_ip}:${remote_port}" , 1024)
    
    tk.case("count > 10").pipe(print , tk.alert , tk.drop) -- 打印, 告警, 删除
    tk.case("count > 100").pipe(print , tk.alert , tk.drop) -- 打印, 告警, 删除
    tk.start()
```

## 风险事件
> 封装每一个触发的事件 event

index可以获取的字段信息如下:
- minion_id
- inet
- class
- level
- payload
- subject
- local_ip
- local_port
- remote_ip
- remote_port
- region
- time
- reference
- alert

内置方法:
- [payloadf(format , v...)](#)&emsp;格式化设置payload
- [subjectf(format , v...)](#)&emsp;格式化设置subject
- [referencef(format , v...)](#)&emsp;格式化设置reference
- [log()](#)&emsp;产生一条日志
- [send()](#)&emsp;上报数据
- [to(pipe)](#)
- [metadata(string , string)](#) &emsp;设置额外的数据存储内容, 满足index的接口，出内置字段外

设置字段:
- 满足newindex 的接口方法 可以设置所有的值

```lua 
    local ev = vela.risk.brute{
      remote_ip   = "1.1.1.1",
      remote_port = 3654,
      reference   = "https://www.baidu.com",
      payload     = f("user:%s pass:%s" , "admin" , "user"),
      subject     = f("mysql暴力破解事件"),
      alert       = true,
    }
    
    ev.payload = "aaaaaa" --利用newindex重新设置值 可以修改所有的键值
    
    ev.metadata("info" , "metadata info")
    ev.send()
    
    print(ev.info) -- 阔以获取
```

## cookie
> 存储一类事件的统计信息

内置函数:
- [pay(string)](#)添加payload
- [set(string , string)](#)设置cookie中的缓存字段;满足index

内置字段:
- count
- from
- count
- state
- payload
- payload_size
- after &emsp;统计时间跟现在相比过去多久了
- 已经所有set的key的值

```lua
    local tk = vela.risk.ticker{name="hh"}
    tk.start()
    tk.case("after > 100").pipe(tk.drop)

    tk.hook(function(cookie , ev)
        cookie.pay(ev.from)
        cookie.pay(ev.dst_port)
        cookie.set("local_ip" , ev.local_ip) --优先级小于by设置的local_ip 
        cookie.set("info" , "rule xxx 123")  --优先级小于by设置的local_ip 
        
        print(cookie.info)    --直接阔以获取
    end)
```

## 完整案例1
> 登录限制频率

```lua
local debug = vela.Debug
local pretty = vela.pretty

local success = {} -- 登录成功记录
local failed = {} -- 登录失败记录


function failed.push(ev)
    local addr = ev.addr
    local n = failed.addr or 0
    failed.addr = n + 1
end

function success.push(ev)
    local addr = ev.addr
    local n = success.addr or 0
    success.addr = n + 1
end

local function alarm(tx , id , cond)
    local key = tx.id 
    local cookie = tx.cookie
  
    local r_ev  = vela.risk.login{
      subject   = "发现异常登录",
      remote_ip = tx.remote_ip,
      local_ip  = vela.inet(),
      payload   = cookie.payload,
      alert     = true,
      level     = "高危",
    }    
    r_ev.ding("emc:140996:张三" ,  -- 格式  通知类型:号码:备注
              "emc:12200:李四" ,   
              "mail:1@a.com:证券")
    
    r_ev.send() 
    debug("cookie:%v\nid:%d\ncond:%s" , pretty(tx) , id , cond)
end


-- 告警抑制
local tk  = vela.risk.ticker("ticker")
tk.level("高危")
tk.class(vela.risk.TLogin)
tk.db("VELA_LOGON_TICKER_DB")
tk.subject("发现异常登录")
tk.by("remote_ip")

tk.case("count > 2").pipe(alarm)
-- tk.case("count > 3").pipe(print , tk.alert  )
tk.case("after > 60").pipe(tk.drop)
tk.start()

vela.Debug("异常登录告警 service start")
local s = vela.logon.success()
s.history(success.push)
s.pipe(success.push , function(v)
    debug("login success ---- %-v",v)
end)
s.start()

local fail = vela.logon.fail()
fail.history(failed.push)
fail.pipe(failed.push , function(ev)
    debug("login failed ---- [logon event] %-v",pretty(ev))
    local cookie = tk.event(ev.risk())
    cookie.pay(ev.user)
    cookie.save()
end)
fail.start()
```