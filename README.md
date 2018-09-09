``` bash
# install dependencies
npm install

# serve with hot reload at localhost:8080
npm run dev

```



# 最近的一个vue小项目需要node服务端做一个用户登录的校验以及权限拦截（用户认证与授权），目前常用的有两种----**JWT和Session**

### -1.传统的session+cookie 身份验证(Seesion)
   由于HTTP是无状态的，它并不记录用户的身份，用户将账户与密码发送到服务器后，后台通过校验，但并没有记录状态，于是下一次用户的请求仍需要校验份 为了解决这个问题需要在服务端生成一条包含用户身份的记录，也就是session，在将这条记录发送给用户存储在本地，即cookie，之后用户的请求都会带上这条cookie,若客户端的cookie与服务端的seesion都是一致的，则说明身份验证通过。

### -2.token身份验证（JWT）
   流程图
   ![image](https://upload-images.jianshu.io/upload_images/2047545-ce2ac0ef75f87a8c..png?imageMogr2/auto-orient/strip%7CimageView2/2/w/552/format/webp)
   
   流程大致过程：
   
-         第一次请求时，用户发送账户和密码
-         后台校验通过，会生成一个有效性的token,再将token发送给用户
-         用户获取到token后，存到本地的cookie或者是localstorage 中
-         之后的每次api请求都会将token添加到请求头信息，所有需要校验身份的api都会被校验token若token解析后的数据包含用户信息，则身份验证通过
   
   


#####     Seesion与token校验中 token的优点： 

- 在基于token的认证，token通过请求头传输，而不是把认证信息存储在session或者cookie中。这意味着无状态。你可以从任意一种可以发送HTTP请求的终端向服务器发送请求。
- 可以避免CSRF攻击
- 当在应用中进行 session的读，写或者删除操作时，会有一个文件操作发生在操作系统的temp 文件夹下，至少在第一次时。假设有多台服务器并且 session 在第一台服务上创建。当你再次发送请求并且这个请求落在另一台服务器上，session 信息并不存在并且会获得一个“未认证”的响应。我知道，你可以通过一个粘性 session 解决这个问题。然而，在基于 token 的认证中，这个问题很自然就被解决了。没有粘性 session 的问题，因为在每个发送到服务器的请求中这个请求的 token 都会被拦截。



有人疑惑的上面不是说jwt校验嘛，怎么没提到jwt 是啥？ 这里就进行补充一下jwt的专业描述：
> JWT(JSON Web Token),字面意思很好理解，就是Web的JSON令牌。一种通过Web可以安全传递JSON格式信息的机制。优势体量小，防串改，数据相对安全。可以用于客户端到服务器端重要用户数据保持，验证用户签名数据，也可以用于无状态服务的状态保持。，而我们项目要做的事情，就是用户登录后把用户当前操作的企业关系，以及用户id存储起来。通过网关将JWT解密后，有相关业务权限的API调用都是使用JWT中传递过来的参数进行权限校验。也可以[参考JWT简介或者官方网站jwt.io](https://jwt.io/)

> [JWT 介绍：阮一峰](http://www.ruanyifeng.com/blog/2018/07/json_web_token-tutorial.html)

> 点提示：[token](https://www.jianshu.com/p/310d307e44c6)/[seesion](https://www.jianshu.com/p/310d307e44c6)/[cookie](https://www.jianshu.com/p/310d307e44c6)/[localstorage](https://blog.csdn.net/qq_35585701/article/details/81393361)
>[开发安全的 API 所需要核对的清单](https://github.com/shieldfy/API-Security-Checklist/blob/master/README-zh.md)
示例简介：

#### 登录认证接口认证：

**客户端：**

**在config>index.js配置proxyTable**
  
```
proxyTable: {
'/api': { // '/api':匹配项
    target: 'http://127.0.0.1:3000/',//设置你调用的接口域名和端口号 别忘了加http
    changeOrigin: true,
    pathRewrite: {
      '^/api': ''//这里理解成用‘/api’代替target里面的地址，后面组件中我们掉接口时直接用api代替 比如我要调用'http://127.0.0.1:3000/user/add'，直接写‘/api/user/add’即可
    }
  }
},
```
**使用axios进行登录以及验证拦截:拦截器**
>   http.js来配置axios拦截器，统一处理所有http请求和响应，就得用上 axios 的拦截器。通过配置http resquest interceptors为http头增加Authorization字段，其内容为Token，通过配置http response interceptors，当后端接口返回401 Unauthorized（未授权），让用户重新登录。


```
import axios from 'axios'

const http = axios.create({
  // timeout:10000,
  // baseURL: '',
  // method: 'post'
})
// http request 拦截器
// 每次请求都为http头增加Authorization字段，其内容为Token
http.interceptors.request.use(
  config => {
    const token = localStorage.getItem('token');
    if (token) {
      config.headers.common['Authorization'] = token;
      // config.headers['token'] = token
    }
    console.log(config)
    return config;
  },
  error => {
    return Promise.reject(error);
  }
);

// http response 拦截器
http.interceptors.response.use(response => {
  let data = response.data
  //返回状态值是200 即返回数据
  if (data.code === 200) {
    return data.data
  }
  //返回状态值401即跳转到登录页面
  if (data.code === 401) {
    window.location.href = '/login'
  }
  // let msg = data.code ? data.msg : `${response.config.headers['method']} : ${data.error}`
  // data.message = msg
  return Promise.reject(data)
}, error => {
  // if (error.response) {
  //   switch (error.response.status) {
  //     case 401:
  //       // 这里写清除token的代码
  //       localStorage.removeItem(token);
  //       router.replace({
  //         path: 'login',
  //         query: {redirect: router.currentRoute.fullPath}//登录成功后跳入浏览的当前页面
  //       })
  //   }
  // }
  // return Promise.reject(error.response.data)
  // if (error.code === 'ECONNABORTED' && error.message.indexOf('timeout') !== -1) {
  //   error.msg = '请求超时，请重试'
  // }
  return Promise.reject(error)
})

export default http

```

**login.vue登录页面的设计：通过axios 发送账户/密码并接受返回数据token**

```
<script>
export default {
  name: 'login',
  data () {
    return {
        loginForm: {
          name: "liu",
          password: '1234'
        },
    }
  },
  methods:{
    login(){
      this.$http.post('/api/login', this.loginForm).then(res => {
          localStorage.setItem('token', res)
          location.replace('/index')
           console.log(res);
           
      })
      
      
    }
  }
}
</script>
```

      

      

**服务端：**

**在api.js中进行api校验**
       在数据库中查找用户的信息，如果找到说明用户存在 根据用户的数量来判断判断是否存在即可
       数据检索成功，将用户信息加密为token 
       将token返回
       
```
import {Router} from 'express'
import jwt from 'jsonwebtoken'
import retoken from './retoken'
import indexController from '../controllers'

const router = Router()
//设置跨域
router.all('*', function(req, res, next) {
  res.header("Access-Control-Allow-Origin", "*");
  res.header("Access-Control-Allow-Headers", "Content-Type,Content-Length, Authorization, Accept,X-Requested-With");
  res.header("Access-Control-Allow-Methods","PUT,POST,GET,DELETE,OPTIONS");
  res.header("Access-Control-Request-Headers:content-type,xfilecategory,xfilename,xfilesize");
  res.header("X-Powered-By",' 3.2.1')
  if(req.method=="OPTIONS") res.send(200);/*让options请求快速返回*/
  else  next();
});
//添加token认证
router.use(retoken)

/**
 * 登录验证:
 * *首先获取提交的用户名和密码
 * *查询数据库是否存在账户名 存在则生成token
 * *
 * */
router.use('/login', (req, res, next) => {
  console.log('进入登录验证模块');
  //登录验证获取前端传来的用户表单用户名和密码参数
  let username = req.body.username ;
  let password = req.body.password ;
  console.log(username, password);
  
  

  //在数据库中查找用户的信息，如果找到说明用户存在 根据用户的数量来判断判断是否存在即可
  //使用数据库查询  User.count({'username': username ,'password':password})
  let count = 2;

    if(count > 1) {
      //生成秘钥
      var jwtTokenSecret = 'fjJWT' ;
      //生成token  
      const userToken = {
        username,
        password,
        loginAt: +new Date
      }
      //签发token 指定过期时间2h
      const token = jwt.sign(userToken, jwtTokenSecret, { expiresIn: '2h' });
      res.json({
        code: 200,
        data: token
      })
    }
})

router.use('/index', (req, res, next) => {
    res.json({
        code: 200,
        data: 'henhao'
    })
})
//路由
router.use('/user',indexController)
export default router
```

**retoken.js token认证**

```
mport jwt from "jsonwebtoken";
import api from "./unLogin";
let unLogin = api.unLogin
export default function (req, res, next) {
  let method = req.method.toLowerCase()
  let path = req.path
    //接口不需要登陆：直接next
    //判断method类型，并且是否包含path
    if(unLogin[method] && unLogin[method].indexOf(path) !== -1){
      console.log('这个api 不需要验证token的')
      return  next()
    }
    const token = req.headers.authorization
    // console.log(req.headers)
  //没有token值，返回401
  //秘钥
  var jwtTokenSecret = 'fjJWT' ;

    if (!token) {
        return res.json({
            code: 401,
            msg: 'you need login:there is no token'
        })
    }

    /**
     * 解析token是否过期 和是否是正确的token
     */
    jwt.verify(token, jwtTokenSecret, (err, decoded) => {
        console.log('已验证token 是正确的')
        if(err){
            return res.json({
                code: 401,
                msg: err.msg
            })
        } else {
          // 将携带的信息赋给req.user
            req.user = decoded
            return next()
        }
    })
}
```
