"use strict";(self.webpackChunk=self.webpackChunk||[]).push([[507],{"./js/api/commands/user/email/accounts/index.js":function(g,f,s){s.r(f),s.d(f,{$processors:function(){return E},changeDKIMStatus:function(){return x},changePassword:function(){return A},createAccount:function(){return n},deleteAccounts:function(){return a},getAccounts:function(){return v},getLoginsList:function(){return y},modifyAccount:function(){return d},purgeAccounts:function(){return t},suspendAccounts:function(){return u},unsuspendAccounts:function(){return l},webmailSSO:function(){return h}});var e=s("./js/api/command/index.js"),c=s("../node_modules/monet/dist/monet.js"),p=s.n(c),_=s("./js/api/converters.js");const i=o=>c.Maybe.Some(o).map(Number).filter(Number.isFinite).orSome(1/0),E={sent:o=>c.Maybe.fromNull(o).filter(m=>typeof m=="object").flatMap(({sent:m,send_limit:I})=>{try{return c.Maybe.Some({usage:i(m),limit:i(I)})}catch(D){return c.Maybe.None()}}).orSome(!1),lastChange:o=>c.Maybe.fromNull(o).map(({ip:m,when:I})=>({ip:(0,c.Identity)(m).map(_.toAppString).map(_.toAppText).get(),when:(0,c.Identity)(I).map(_.toAppDate).get()})).orSome(!1)},v=e.Z.get({id:"EMAIL_ACCOUNTS",url:"/CMD_EMAIL_POP",domain:!0,pagination:!0,params:{bytes:!0},after:o=>o.flow(o.wrap("options"),o.moveProp({"options.emails":"emails","options.EMAIL_MESSAGE":"options.email_message"}),o.mapProps({emails:o.toTable(o.mapArray(o.flow(o.moveProp({"usage.last_login":"last_login","usage.last_password_change":"last_password_change"}),o.mapProps({login:m=>m.includes("@")?m.split("@")[0]:m,is_default:(m,{login:I})=>!I.includes("@"),sent:E.sent,usage:o.mapValues(i),last_login:E.lastChange,last_password_change:E.lastChange})))),options:o.mapProps({DKIM:o.isEqual("1"),DKIM_ENABLED:o.isEqual("1"),block_cracking_unblock:o.convert.toAppNumber,clean_forwarders_on_email_delete:o.isEqual("1"),count_pop_usage:o.isEqual("1"),pop_disk_usage_cache:o.isEqual("1"),pop_disk_usage_true_bytes:o.isEqual("1"),user_can_set_email_limit:o.isEqual("1"),purge_select:o.toSelect,when_select:o.toSelect,HAVE_ONE_CLICK_WEBMAIL_LOGIN:o.convert.toAppBoolean,system_user_to_virtual_passwd:o.isEqual("1")})}))}),r=e.Z.post({url:"/CMD_EMAIL_POP",params:{action:"delete"},domain:!0}),u=r.extend({params:{suspend:!0}}),l=r.extend({params:{unsuspend:!0}}),a=r.extend({params:{delete:!0},schema:{clean_forwarders:e.Z.REQUIRED_BOOL}}),t=r.extend({params:{purge:!0},body:{file:e.Z.REQUIRED_STRING,what:e.Z.REQUIRED_STRING}}),n=e.Z.post({url:"/CMD_EMAIL_POP",params:{action:"create"},domain:!0,schema:{user:e.Z.USER,passwd2:e.Z.PASSWORD,passwd:e.Z.PASSWORD,quota:e.Z.REQUIRED_STRING,limit:e.Z.OPTIONAL_STRING},after:o=>o.mapProp("result",m=>m.replace(/(\\n)+/g,`
`))}),d=e.Z.post({url:"/CMD_EMAIL_POP",params:{action:"modify"},domain:!0,schema:{user:e.Z.USER,newuser:e.Z.USER,passwd2:e.Z.OPTIONAL_STRING,passwd:e.Z.OPTIONAL_STRING,quota:e.Z.REQUIRED_STRING,limit:e.Z.OPTIONAL_STRING}}),A=e.Z.post({url:"/CMD_CHANGE_EMAIL_PASSWORD",schema:{email:e.Z.REQUIRED_STRING,oldpassword:e.Z.REQUIRED_STRING,password1:e.Z.REQUIRED_STRING,password2:e.Z.REQUIRED_STRING}}),x=e.Z.post({url:"/CMD_EMAIL_POP",domain:!0,schema:{action:e.Z.REQUIRED_STRING},before:({action:o})=>({action:"set_dkim",[o]:!0})}),h=e.Z.post({url:"/CMD_WEBMAIL_LOGIN",notifySuccess:!1,schema:{email:e.Z.REQUIRED_STRING}}),y=e.Z.get({id:"LOGINS_LIST",url:"/CMD_EMAIL_POP",domain:!0,response:[],params:{quick:!0},mapResponse:o=>o.emails})},"./js/api/commands/validation/index.js":function(g,f,s){s.d(f,{i9:function(){return d},ty:function(){return t},l7:function(){return l},OE:function(){return n},ub:function(){return y},oH:function(){return v},U5:function(){return r},k_:function(){return E},PR:function(){return a},uo:function(){return h},Jj:function(){return x},rV:function(){return A}});var e=s("./js/api/command/index.js"),c=s("../node_modules/punycode/punycode.es6.js"),p=s("./js/api/commands/converters/index.ts"),_={isValid(m){return typeof m.error=="undefined"},getMessage(m){return(0,p.S8)(m.error||"")}};const i=e.Z.get({url:"/CMD_JSON_VALIDATE",schema:{value:e.Z.REQUIRED_STRING},response:{valid:!0,message:""},mapResponse:{valid:_.isValid,message:_.getMessage}}),E=i.extend({id:"VALIDATE_FORWARDER",params:{type:"forwarder",ignore_system_default:!0}}),v=i.extend({id:"VALIDATE_EMAIL",params:{type:"email",check_mailing_list:!0},schema:{check_exists:{type:Boolean,required:!1,default:!0}}}),r=i.extend({id:"VALIDATE_FTP",params:{type:"ftp"},domain:!0}),u=i.extend({params:{type:"dns"},domain:!0,schema:{record:e.Z.REQUIRED_STRING}}),l=u.extend({id:"VALIDATE_DNS_VALUE",params:{check:"value",name:!0},domain:!0,schema:{value:e.Z.REQUIRED_STRING}}),a=l.extend({id:"VALIDATE_MX_VALUE",params:{record:"MX"},before:({value:m})=>({value:"10",mx_value:m})}),t=u.extend({id:"VALIDATE_DNS_NAME",params:{check:"name",value:!0,mx_value:!0},schema:{name:e.Z.REQUIRED_STRING,value:null}}),n=i.extend({id:"VALIDATE_DATABASE",params:{type:"dbname"}}),d=i.extend({id:"VALIDATE_DATABASE_USER",params:{type:"dbusername"}}),A=i.extend({id:"VALIDATE_USERNAME",params:{type:"username"}}),x=i.extend({id:"VALIDATE_SUBDOMAIN",domain:!0,params:{type:"subdomain"}}),h=i.extend({id:"VALIDATE_PASSWORD",params:{type:"password"}}),y=i.extend({id:"VALIDATE_DOMAIN",params:{type:"domain"},before:({value:m})=>({value:c.ZP.toASCII(m)})}),o=i.extend({id:"VALIDATE_IP_RANGE_LIST",params:{type:"ip_range_list"}})},"./js/api/commands/converters/customItems.ts":function(g,f,s){s.d(f,{CR:function(){return i}});var e=s("../node_modules/ramda/es/index.js"),c=s("./js/api/commands/converters/index.ts"),p=s("./js/api/commands/utils/transduce.ts"),_=s("./js/api/commands/converters/toSelectData.ts");const i=r=>{const u={name:r.name,type:r.type==="listbox"?"select":r.type,label:r.string,description:r.desc||"",value:r.type==="checkbox"?(0,c.sw)(r.checked||"no"):r.value||""};return u.type==="select"?e.BPw(u,(0,_.M1)(r.select||{})):u},E=r=>(0,p.vr)([(0,p.uD)(u=>/^item\d+val$/.test(u)),(0,p.r5)(u=>{const l=u,a=u.replace("val","txt"),t=r[l],n=r[a];return{[t]:n}})],Object.keys(r)),v=(r,u)=>e.qCK(a=>{const t={name:a.name,type:a.type==="listbox"?"select":a.type,description:a.desc||"",value:a.value||"",label:a.string};return a.type==="listbox"?(t.value=a.default,t.options=E(a)):a.type==="checkbox"&&(t.value=a.checked==="yes"),t},e.BPw({name:r}),(0,p.vr)([(0,p.r5)(a=>{const[t,n]=e.Vl2("=",a);return{[t]:n}})]),e.Vl2("&"))(u);f.ZP={fromObject:i,fromString:v}},"./js/api/commands/converters/index.ts":function(g,f,s){s.d(f,{l$:function(){return l.ZP},t0:function(){return e.t0},S8:function(){return e.S8},ql:function(){return e.ql},sw:function(){return e.sw},Qu:function(){return e.Qu},He:function(){return e.He},M1:function(){return u.M1},sf:function(){return t},cc:function(){return r}});var e=s("./js/api/commands/converters/primitive.ts"),c=s("../node_modules/monet/dist/monet.js"),p=s("./js/api/commands/types.ts");const _=n=>typeof n=="object"?c.Either.Right(n):c.Either.Left(new Error("Passed param is not an object")),i=n=>typeof n.usage=="string"?c.Either.Right(n):c.Either.Left(new Error("usage property is required")),E=n=>({usage:(0,e.He)(n.usage),limit:(0,e.Qu)(n.limit)}),v=({usage:n,limit:d})=>{let A=p.H.Normal;const x=Math.floor(n/d*100);return x>=100?A=p.H.OverUsed:x>80&&(A=p.H.AlmostUsed),{usage:n,limit:d,status:A}},r=n=>{const d=c.Either.Right(n).flatMap(_).flatMap(i).map(E).map(v);if(d.isLeft())throw d.left();return d.right()};var u=s("./js/api/commands/converters/toSelectData.ts"),l=s("./js/api/commands/converters/customItems.ts"),a=s("../node_modules/ramda/es/index.js");const t=n=>d=>{const{info:A}=d,x=a.CEd(["info"],d);return{columns:A.columns,rowsCount:Number(A.rows),rows:a.UID(n,a.VO0(x))}}},"./js/api/commands/converters/toSelectData.ts":function(g,f,s){s.d(f,{M1:function(){return v}});var e=s("../node_modules/monet/dist/monet.js"),c=s.n(e),p=s("./js/api/commands/utils/transduce.ts"),_=s("../node_modules/ramda/es/index.js");const i=r=>e.Maybe.Some(r).flatMap(u=>{const l=u.find(a=>a.selected==="yes");return l?e.Maybe.Some(l):e.Maybe.None()}).flatMap(u=>e.Maybe.fromNull(u.value)).orSome(""),E=(0,p.vr)([(0,p.r5)(r=>({[r.value]:r.text}))]),v=r=>{const u=(0,_.VO0)(r);return{value:i(u),options:E(u)}}},"./js/api/commands/types.ts":function(g,f,s){s.d(f,{H:function(){return e}});var e;(function(c){c.Normal="normal",c.AlmostUsed="almost_used",c.OverUsed="overused"})(e||(e={}))},"./js/api/commands/utils/transduce.ts":function(g,f,s){s.d(f,{Re:function(){return _},r5:function(){return c},uD:function(){return p},vr:function(){return u},zh:function(){return v}});var e=s("../node_modules/ramda/es/index.js");const c=l=>a=>(t,n)=>{const d=l(n);return a(t,d)},p=l=>a=>(t,n)=>l(n)?a(t,n):t,_=(l,a)=>(l.push(a),l),i=(l,a)=>e.BPw(l,a),E=(l,a,t,n)=>{const d=e.qCK(...t);return n.reduce(d(a),l)},v=e.WAo(E),r=v([],_),u=v({},i)},"./js/pages/user/email/accounts/create.vue":function(g,f,s){s.r(f),s.d(f,{default:function(){return l}});var e=function(){var t=this,n=t._self._c;return n("app-page",{scopedSlots:t._u([{key:"default",fn:function(){return[n("app-page-section",[n("ui-form-element",{attrs:{group:"account",validators:{required:!0,validateUser:t.validateUser}},scopedSlots:t._u([{key:"title",fn:function(){return[n("span",{domProps:{textContent:t._s(t.$gettext("Username"))}})]},proxy:!0},{key:"content",fn:function(){return[n("input-text",{attrs:{suffix:`@${t.$domainUnicode}`,vertical:t.clientStore.isPhone},model:{value:t.user,callback:function(d){t.user=d},expression:"user"}})]},proxy:!0},{key:"error:validateUser",fn:function(){return[t._v(`
                    `+t._s(t.$api.emailValidation.message)+`
                `)]},proxy:!0}])}),t._v(" "),n("ui-form-element",{attrs:{group:"account",validators:{required:!0,api:t.$commands.validatePassword}},scopedSlots:t._u([{key:"title",fn:function(){return[n("span",{domProps:{textContent:t._s(t.$gettext("Password"))}})]},proxy:!0},{key:"content",fn:function(){return[n("input-password",{attrs:{"show-generator":""},model:{value:t.password,callback:function(d){t.password=d},expression:"password"}})]},proxy:!0}])}),t._v(" "),n("ui-form-element",{attrs:{group:"account",validators:{required:!0,validateQuota:t.validateQuota},underline:t.$api.setLimit},scopedSlots:t._u([{key:"title",fn:function(){return[n("span",{domProps:{textContent:t._s(t.$gettext("E-mail Quota (MB)"))}})]},proxy:!0},{key:"content",fn:function(){return[n("input-text",{attrs:{disabled:t.quotaUnlimited,number:""},scopedSlots:t._u([{key:"additions:right",fn:function(){return[t.showUnlimitedQuotaCheckbox?n("ui-button",{on:{click:t.toggleQuota}},[n("input-checkbox",{attrs:{model:t.quotaUnlimited}},[n("span",{domProps:{textContent:t._s(t.$gettext("Max"))}})])],1):t._e()]},proxy:!0}]),model:{value:t.quota,callback:function(d){t.quota=d},expression:"quota"}})]},proxy:!0},{key:"error:validateQuota",fn:function(){return[n("span",{domProps:{textContent:t._s(t.$gettext("Quota can't be larger than 100TB"))}})]},proxy:!0}])}),t._v(" "),t.$api.setLimit?n("ui-form-element",{attrs:{group:"account",validators:{validateLimit:t.validateLimit},underline:!1},scopedSlots:t._u([{key:"title",fn:function(){return[n("span",{domProps:{textContent:t._s(t.$gettext("Daily Send Limit"))}})]},proxy:!0},{key:"tooltip",fn:function(){return[n("span",{domProps:{textContent:t._s(t.$gettextInterpolate(t.$gettext("Blank will default to %{ limit }"),{limit:t.maxLimit}))}})]},proxy:!0},{key:"content",fn:function(){return[n("input-text",{attrs:{number:"",placeholder:t.maxLimit,disabled:t.limitUnlimited},scopedSlots:t._u([{key:"additions:right",fn:function(){return[n("ui-button",{attrs:{disabled:!t.canSetUnlimited},on:{click:t.toggleLimit}},[n("input-checkbox",{attrs:{model:t.limitUnlimited}},[n("span",{domProps:{textContent:t._s(t.$gettext("Max"))}})])],1)]},proxy:!0}],null,!1,588535979),model:{value:t.limit,callback:function(d){t.limit=d},expression:"limit"}})]},proxy:!0},{key:"error:validateLimit",fn:function(){return[n("span",{domProps:{textContent:t._s(t.$gettextInterpolate(t.$gettext("Limit can't be larger than %{ limit }"),{limit:t.maxLimit}))}})]},proxy:!0}],null,!1,4161116845)}):t._e()],1)]},proxy:!0},{key:"footer:buttons",fn:function(){return[n("ui-button",{attrs:{theme:"primary",disabled:!t.password,"validate-group":"account"},on:{click:t.createAccount}},[n("span",{domProps:{textContent:t._s(t.$gettext("Create Account"))}})])]},proxy:!0}])})},c=[],p=s("./js/stores/index.ts"),_=s("./js/api/commands/user/email/accounts/index.js"),i=s("./js/api/commands/validation/index.js"),E={preload:_.getAccounts,commands:{validateEmail:i.oH,validatePassword:i.uo},api:[{command:_.getAccounts,bind:{"response.options.user_can_set_email_limit":"setLimit","response.options.GLOBAL_PER_EMAIL_LIMIT":"globalSendLimit","response.options.DEFAULT_POP_QUOTA":"defaultQuota","response.options.MAX_PER_EMAIL_SEND_LIMIT":"maxPerEmailSendLimit","response.options.user_email_quota_max":"emailQuotaMax"}},{command:i.oH,bind:"emailValidation"}],data(){return{user:"",password:"",quota:0,limit:"",quotaUnlimited:!1,limitUnlimited:!0}},computed:{maxLimit(){return this.$api.maxPerEmailSendLimit==="-1"?this.$api.globalSendLimit:this.$api.maxPerEmailSendLimit},canSetUnlimited(){return this.maxLimit==="0"},showUnlimitedQuotaCheckbox(){return this.$api.emailQuotaMax==="0"||this.$api.emailQuotaMax==="-1"||typeof this.$api.emailQuotaMax=="undefined"},...(0,p.Kc)(["client"])},created(){this.quota=this.$api.defaultQuota,this.quotaUnlimited=this.quota==="0",this.limitUnlimited=this.maxLimit==="0"},methods:{createAccount(){(0,_.createAccount)({user:this.user,passwd:this.password,passwd2:this.password,quota:this.quota,limit:this.$api.setLimit?this.limit||this.maxLimit:null}).then(()=>this.$router.back())},validateLimit(a){return this.maxLimit==="0"?!0:Number(a||0)<=Number(this.maxLimit)},async validateUser(a){if(!a)return!0;const{valid:t}=await(0,i.oH)({value:`${a}@${this.$domain}`});return t},toggleLimit(){this.limitUnlimited=!this.limitUnlimited,this.limit=this.limitUnlimited?"0":""},toggleQuota(){this.quotaUnlimited=!this.quotaUnlimited,this.quota=this.quotaUnlimited?"0":this.$api.defaultQuota},validateQuota(a){return Number(a)<=100*2**20}}},v=E,r=s("../node_modules/vue-loader/lib/runtime/componentNormalizer.js"),u=(0,r.Z)(v,e,c,!1,null,null,null),l=u.exports}}]);