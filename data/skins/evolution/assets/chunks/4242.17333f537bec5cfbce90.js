"use strict";(self.webpackChunk=self.webpackChunk||[]).push([[4242],{"../node_modules/date-fns/esm/_lib/requiredArgs/index.js":function(P,f,o){o.d(f,{Z:function(){return a}});function a(u,p){if(p.length<u)throw new TypeError(u+" argument"+(u>1?"s":"")+" required, but only "+p.length+" present")}},"../node_modules/date-fns/esm/isAfter/index.js":function(P,f,o){o.d(f,{Z:function(){return p}});var a=o("../node_modules/date-fns/esm/toDate/index.js"),u=o("../node_modules/date-fns/esm/_lib/requiredArgs/index.js");function p(i,l){(0,u.Z)(2,arguments);var c=(0,a.Z)(i),g=(0,a.Z)(l);return c.getTime()>g.getTime()}},"../node_modules/date-fns/esm/isSameDay/index.js":function(P,f,o){o.d(f,{Z:function(){return i}});var a=o("../node_modules/date-fns/esm/toDate/index.js"),u=o("../node_modules/date-fns/esm/_lib/requiredArgs/index.js");function p(l){(0,u.Z)(1,arguments);var c=(0,a.Z)(l);return c.setHours(0,0,0,0),c}function i(l,c){(0,u.Z)(2,arguments);var g=p(l),m=p(c);return g.getTime()===m.getTime()}},"../node_modules/date-fns/esm/toDate/index.js":function(P,f,o){o.d(f,{Z:function(){return p}});var a=o("../node_modules/date-fns/esm/_lib/requiredArgs/index.js");function u(i){return typeof Symbol=="function"&&typeof Symbol.iterator=="symbol"?u=function(c){return typeof c}:u=function(c){return c&&typeof Symbol=="function"&&c.constructor===Symbol&&c!==Symbol.prototype?"symbol":typeof c},u(i)}function p(i){(0,a.Z)(1,arguments);var l=Object.prototype.toString.call(i);return i instanceof Date||u(i)==="object"&&l==="[object Date]"?new Date(i.getTime()):typeof i=="number"||l==="[object Number]"?new Date(i):((typeof i=="string"||l==="[object String]")&&typeof console!="undefined"&&(console.warn("Starting with v2.0.0-beta.1 date-fns doesn't accept strings as date arguments. Please use `parseISO` to parse strings. See: https://github.com/date-fns/date-fns/blob/master/docs/upgradeGuide.md#string-arguments"),console.warn(new Error().stack)),new Date(NaN))}},"./js/api/commands/user/email/accounts/index.js":function(P,f,o){o.r(f),o.d(f,{$processors:function(){return c},changeDKIMStatus:function(){return N},changePassword:function(){return M},createAccount:function(){return y},deleteAccounts:function(){return A},getAccounts:function(){return g},getLoginsList:function(){return t},modifyAccount:function(){return S},purgeAccounts:function(){return _},suspendAccounts:function(){return R},unsuspendAccounts:function(){return x},webmailSSO:function(){return r}});var a=o("./js/api/command/index.js"),u=o("../node_modules/monet/dist/monet.js"),p=o.n(u),i=o("./js/api/converters.js");const l=e=>u.Maybe.Some(e).map(Number).filter(Number.isFinite).orSome(1/0),c={sent:e=>u.Maybe.fromNull(e).filter(n=>typeof n=="object").flatMap(({sent:n,send_limit:s})=>{try{return u.Maybe.Some({usage:l(n),limit:l(s)})}catch(D){return u.Maybe.None()}}).orSome(!1),lastChange:e=>u.Maybe.fromNull(e).map(({ip:n,when:s})=>({ip:(0,u.Identity)(n).map(i.toAppString).map(i.toAppText).get(),when:(0,u.Identity)(s).map(i.toAppDate).get()})).orSome(!1)},g=a.Z.get({id:"EMAIL_ACCOUNTS",url:"/CMD_EMAIL_POP",domain:!0,pagination:!0,params:{bytes:!0},after:e=>e.flow(e.wrap("options"),e.moveProp({"options.emails":"emails","options.EMAIL_MESSAGE":"options.email_message"}),e.mapProps({emails:e.toTable(e.mapArray(e.flow(e.moveProp({"usage.last_login":"last_login","usage.last_password_change":"last_password_change"}),e.mapProps({login:n=>n.includes("@")?n.split("@")[0]:n,is_default:(n,{login:s})=>!s.includes("@"),sent:c.sent,usage:e.mapValues(l),last_login:c.lastChange,last_password_change:c.lastChange})))),options:e.mapProps({DKIM:e.isEqual("1"),DKIM_ENABLED:e.isEqual("1"),block_cracking_unblock:e.convert.toAppNumber,clean_forwarders_on_email_delete:e.isEqual("1"),count_pop_usage:e.isEqual("1"),pop_disk_usage_cache:e.isEqual("1"),pop_disk_usage_true_bytes:e.isEqual("1"),user_can_set_email_limit:e.isEqual("1"),purge_select:e.toSelect,when_select:e.toSelect,HAVE_ONE_CLICK_WEBMAIL_LOGIN:e.convert.toAppBoolean,system_user_to_virtual_passwd:e.isEqual("1")})}))}),m=a.Z.post({url:"/CMD_EMAIL_POP",params:{action:"delete"},domain:!0}),R=m.extend({params:{suspend:!0}}),x=m.extend({params:{unsuspend:!0}}),A=m.extend({params:{delete:!0},schema:{clean_forwarders:a.Z.REQUIRED_BOOL}}),_=m.extend({params:{purge:!0},body:{file:a.Z.REQUIRED_STRING,what:a.Z.REQUIRED_STRING}}),y=a.Z.post({url:"/CMD_EMAIL_POP",params:{action:"create"},domain:!0,schema:{user:a.Z.USER,passwd2:a.Z.PASSWORD,passwd:a.Z.PASSWORD,quota:a.Z.REQUIRED_STRING,limit:a.Z.OPTIONAL_STRING},after:e=>e.mapProp("result",n=>n.replace(/(\\n)+/g,`
`))}),S=a.Z.post({url:"/CMD_EMAIL_POP",params:{action:"modify"},domain:!0,schema:{user:a.Z.USER,newuser:a.Z.USER,passwd2:a.Z.OPTIONAL_STRING,passwd:a.Z.OPTIONAL_STRING,quota:a.Z.REQUIRED_STRING,limit:a.Z.OPTIONAL_STRING}}),M=a.Z.post({url:"/CMD_CHANGE_EMAIL_PASSWORD",schema:{email:a.Z.REQUIRED_STRING,oldpassword:a.Z.REQUIRED_STRING,password1:a.Z.REQUIRED_STRING,password2:a.Z.REQUIRED_STRING}}),N=a.Z.post({url:"/CMD_EMAIL_POP",domain:!0,schema:{action:a.Z.REQUIRED_STRING},before:({action:e})=>({action:"set_dkim",[e]:!0})}),r=a.Z.post({url:"/CMD_WEBMAIL_LOGIN",notifySuccess:!1,schema:{email:a.Z.REQUIRED_STRING}}),t=a.Z.get({id:"LOGINS_LIST",url:"/CMD_EMAIL_POP",domain:!0,response:[],params:{quick:!0},mapResponse:e=>e.emails})},"./js/openapi/vacations.ts":function(P,f,o){o.d(f,{CP:function(){return m},Mw:function(){return g},VO:function(){return R},de:function(){return c}});var a=o("./js/api/openapi/index.ts"),u=o("../node_modules/runtypes/lib/index.js"),p=o.n(u),i=o("./js/openapi/web.types.ts");const l=(0,a.$d)(),c=a.an.Default(async(x,A)=>{const{data:_}=await l.get(`/api/emailvacation/${x}`,A);return _.status==="success"&&u.Dictionary(i.fi).guard(_.data)===!1?l.failure({type:"INVALID_RESPONSE",response:_.data}):_}),g=a.an.Default(async(x,A,_)=>{const{data:y}=await l.get(`/api/emailvacation/${x}/${A}`,_);return y.status==="success"&&i.mN.guard(y.data)===!1?l.failure({type:"INVALID_RESPONSE",response:y.data}):y}),m=a.an.Default(async(x,A,_,y)=>{const{data:S}=await l.put(`/api/emailvacation/${x}/${A}`,_,y);return S}),R=a.an.Default(async(x,A,_)=>{const{data:y}=await l.delete(`/api/emailvacation/${x}/${A}`,_);return y})},"./js/pages/user/email/vacations/reply-intervals.ts":function(P,f,o){o.d(f,{x:function(){return g}});var a=o("./js/composables/index.ts");const{$ngettext:u,$gettextInterpolate:p}=(0,a.st)(),i=m=>[m*60,p(u("%{m} minute","%{m} minutes",m),{m})],l=m=>[m*3600,p(u("%{h} hour","%{h} hours",m),{h:m})],c=m=>[m*24*3600,p(u("%{d} day","%{d} days",m),{d:m})],g=Object.fromEntries([i(1),i(10),i(30),l(1),l(2),l(6),l(12),c(1),c(2),c(3),c(4),c(5),c(6),c(7)])},"./js/pages/user/email/vacations/create.vue":function(P,f,o){o.r(f),o.d(f,{default:function(){return N}});var a=function(){var t=this,e=t._self._c,n=t._self._setupProxy;return e("app-page",{scopedSlots:t._u([{key:"default",fn:function(){return[e("app-page-section",[e("ui-form-element",{attrs:{group:"vacation",validators:{required:!0,validateVacationAccount:n.validateVacationAccount}},scopedSlots:t._u([{key:"title",fn:function(){return[e("span",{domProps:{textContent:t._s(n.$gettext("Vacation Account:"))}})]},proxy:!0},{key:"content",fn:function(){return[e("input-select",{attrs:{options:n.accountNames},scopedSlots:t._u([{key:"additions:right",fn:function(){return[t._v(`
                            @`+t._s(n.domainUnicode)+`
                        `)]},proxy:!0}]),model:{value:n.vacation.user,callback:function(s){t.$set(n.vacation,"user",s)},expression:"vacation.user"}})]},proxy:!0},{key:"error:validateVacationAccount",fn:function(){return[e("span",{domProps:{textContent:t._s(n.$gettext("Already exists"))}})]},proxy:!0}])}),t._v(" "),e("ui-form-element",{attrs:{group:"vacation"},scopedSlots:t._u([{key:"title",fn:function(){return[e("span",{domProps:{textContent:t._s(n.$gettext("Plain Content"))}})]},proxy:!0},{key:"content",fn:function(){return[e("input-checkbox",{model:{value:n.vacation.plainContent,callback:function(s){t.$set(n.vacation,"plainContent",s)},expression:"vacation.plainContent"}})]},proxy:!0}])}),t._v(" "),e("ui-form-element",{attrs:{validators:{required:!0,regex:n.regex}},scopedSlots:t._u([{key:"title",fn:function(){return[e("span",{domProps:{textContent:t._s(n.$gettext("Subject Prefix"))}})]},proxy:!0},{key:"content",fn:function(){return[e("input-text",{attrs:{suffix:n.$gettext(": original subject")},model:{value:n.vacation.subjectPrefix,callback:function(s){t.$set(n.vacation,"subjectPrefix",s)},expression:"vacation.subjectPrefix"}})]},proxy:!0},{key:"error:regex",fn:function(){return[e("span",{domProps:{textContent:t._s(n.$gettext("Invalid Subject"))}})]},proxy:!0}])}),t._v(" "),e("ui-form-element",{attrs:{group:"vacation",validators:{required:!0}},scopedSlots:t._u([{key:"title",fn:function(){return[e("span",{domProps:{textContent:t._s(n.$gettext("Vacation Start"))}})]},proxy:!0},{key:"content",fn:function(){return[e("input-datetime",{attrs:{min:n.today,"show-seconds":!0,"let-select-day":n.today},model:{value:n.vacation.startTime,callback:function(s){t.$set(n.vacation,"startTime",s)},expression:"vacation.startTime"}})]},proxy:!0}])}),t._v(" "),e("ui-form-element",{attrs:{group:"vacation",validators:{required:!0,validateTime:n.validateTime}},scopedSlots:t._u([{key:"title",fn:function(){return[e("span",{domProps:{textContent:t._s(n.$gettext("Vacation End"))}})]},proxy:!0},{key:"content",fn:function(){return[e("input-datetime",{ref:"endinput",attrs:{min:n.vacation.startTime,"show-seconds":!0,"let-select-day":n.vacation.startTime},model:{value:n.vacation.endTime,callback:function(s){t.$set(n.vacation,"endTime",s)},expression:"vacation.endTime"}})]},proxy:!0},{key:"error:validateTime",fn:function(){return[e("span",{domProps:{textContent:t._s(n.$gettext("End time should be larger than start time"))}})]},proxy:!0}])}),t._v(" "),e("ui-form-element",{scopedSlots:t._u([{key:"title",fn:function(){return[e("span",{domProps:{textContent:t._s(n.$gettext("Reply Frequency"))}})]},proxy:!0},{key:"tooltip",fn:function(){return[e("span",{domProps:{textContent:t._s(n.$gettext("Minimum time before a repeated reply"))}})]},proxy:!0},{key:"content",fn:function(){return[e("input-select",{attrs:{options:n.replyIntervals},model:{value:n.vacation.replyIntervalSec,callback:function(s){t.$set(n.vacation,"replyIntervalSec",s)},expression:"vacation.replyIntervalSec"}})]},proxy:!0}])}),t._v(" "),e("ui-form-element",{attrs:{group:"vacation",validators:{required:!0}},scopedSlots:t._u([{key:"title",fn:function(){return[e("span",{domProps:{textContent:t._s(n.$gettext("Vacation Message:"))}})]},proxy:!0},{key:"content",fn:function(){return[e("input-textarea",{model:{value:n.vacation.message,callback:function(s){t.$set(n.vacation,"message",s)},expression:"vacation.message"}})]},proxy:!0}])})],1)]},proxy:!0},{key:"footer:buttons",fn:function(){return[e("ui-button",{attrs:{theme:"primary",disabled:!t.$valid("vacation")},on:{click:n.createVacation}},[e("span",{domProps:{textContent:t._s(n.$gettext("Create"))}})])]},proxy:!0}])})},u=[],p=o("../node_modules/vue/dist/vue.common.prod.js"),i=o("./js/composables/index.ts"),l=o("../node_modules/vue-router/composables.mjs"),c=o("./js/api/commands/user/email/accounts/index.js"),g=o("./js/openapi/vacations.ts"),m=o("../node_modules/ramda/es/index.js"),R=o("../node_modules/date-fns/esm/isAfter/index.js"),x=o("../node_modules/date-fns/esm/isSameDay/index.js"),A=o("./js/pages/user/email/vacations/reply-intervals.ts"),_=(0,p.defineComponent)({__name:"create",setup(r){const{$gettext:t}=(0,i.st)(),{domain:e,domainUnicode:n}=(0,i.ay)(),s=(0,i.d$)(),D=(0,l.tv)(),E=v=>m.UID(m.zXx(["account","is_default"]))(m.VO0(v)),h=(0,i.Lu)({},t("Vacation Messages")),I=(0,p.ref)([]),d=(0,p.reactive)({user:"",message:"",startTime:new Date,endTime:new Date,subjectPrefix:"",plainContent:!1,replyIntervalSec:"86400"}),$=/^[\p{L}\p{N}\s]+$/u,b=(0,p.computed)(()=>{const v=new Date;return v.setHours(0,0,0),v}),T=(0,p.computed)(()=>m.UID(v=>v.account)(I.value)),C=(0,p.computed)(()=>({message:d.message,startTime:O(d.startTime),endTime:O(d.endTime),plainContent:d.plainContent,subjectPrefix:d.subjectPrefix,replyIntervalSec:Number(d.replyIntervalSec)}));(0,c.getAccounts)({ipp:9999}).then(v=>{I.value=E(v.emails.rows);const j=m.sEJ(m.OH4("is_default",!0))(I.value);j&&(d.user=j.account)}),(0,p.watch)(d,()=>{(0,R.Z)(d.startTime,d.endTime)&&(d.endTime=d.startTime)});function O(v){return v.toISOString()}async function Z(){(0,g.CP)(e.value,d.user,C.value).then(v=>{v.status==="success"&&(s.success({title:t("Vacation Messages"),content:t("Vacation message succesffully created!")}),D.push({name:"user/email/vacations"})),v.error&&h(v.error)})}async function w(v){if(v){let j=!1;return await(0,g.Mw)(e.value,v).then(L=>{L.error&&L.error.type==="NOT_FOUND"&&(j=!0)}),j}return!0}function U(){return(0,x.Z)(d.startTime,d.endTime)?d.endTime>d.startTime:!0}return{__sfc:!0,$gettext:t,domain:e,domainUnicode:n,notify:s,router:D,formatAccounts:E,errorMessages:h,accounts:I,vacation:d,regex:$,today:b,accountNames:T,requestData:C,toAPIDate:O,createVacation:Z,validateVacationAccount:w,validateTime:U,replyIntervals:A.x}}}),y=_,S=o("../node_modules/vue-loader/lib/runtime/componentNormalizer.js"),M=(0,S.Z)(y,a,u,!1,null,null,null),N=M.exports},"../node_modules/vue-router/composables.mjs":function(P,f,o){o.d(f,{tv:function(){return p},yj:function(){return i}});var a=o("../node_modules/vue/dist/vue.common.prod.js");/*!
  * vue-router v3.6.5
  * (c) 2022 Evan You
  * @license MIT
  */function u(r){if(!getCurrentInstance())throw new Error("[vue-router]: Missing current instance. "+r+"() must be called inside <script setup> or setup().")}function p(){return(0,a.getCurrentInstance)().proxy.$root.$router}function i(){var r=(0,a.getCurrentInstance)().proxy.$root;if(!r._$route){var t=(0,a.effectScope)(!0).run(function(){return(0,a.shallowReactive)(Object.assign({},r.$router.currentRoute))});r._$route=t,r.$router.afterEach(function(e){Object.assign(t,e)})}return r._$route}function l(r){return x(r,c)}function c(r,t,e){var n=r.matched,s=t.matched;return n.length>=e&&n.slice(0,e+1).every(function(D,E){return D===s[E]})}function g(r,t,e){var n=r.matched,s=t.matched;return n.length<e||n[e]!==s[e]}function m(r){return x(r,g)}var R=function(){};function x(r,t){for(var e=getCurrentInstance(),n=p(),s=e.proxy;s&&s.$vnode&&s.$vnode.data&&s.$vnode.data.routerViewDepth==null;)s=s.$parent;var D=s&&s.$vnode&&s.$vnode.data?s.$vnode.data.routerViewDepth:null;if(D!=null){var E=n.beforeEach(function(h,I,d){return t(h,I,D)?r(h,I,d):d()});return onUnmounted(E),E}return R}function A(r){if(!(r.metaKey||r.altKey||r.ctrlKey||r.shiftKey)&&!r.defaultPrevented&&!(r.button!==void 0&&r.button!==0)){if(r.currentTarget&&r.currentTarget.getAttribute){var t=r.currentTarget.getAttribute("target");if(/\b_blank\b/i.test(t))return}return r.preventDefault&&r.preventDefault(),!0}}function _(r,t){var e=function(D){var E=t[D],h=r[D];if(typeof E=="string"){if(E!==h)return{v:!1}}else if(!Array.isArray(h)||h.length!==E.length||E.some(function(I,d){return I!==h[d]}))return{v:!1}};for(var n in t){var s=e(n);if(s)return s.v}return!0}function y(r,t){return Array.isArray(r)?S(r,t):Array.isArray(t)?S(t,r):r===t}function S(r,t){return Array.isArray(t)?r.length===t.length&&r.every(function(e,n){return e===t[n]}):r.length===1&&r[0]===t}function M(r,t){if(Object.keys(r).length!==Object.keys(t).length)return!1;for(var e in r)if(!y(r[e],t[e]))return!1;return!0}function N(r){var t=p(),e=i(),n=computed(function(){return t.resolve(unref(r.to),e)}),s=computed(function(){var I=n.value.route,d=I.matched,$=d.length,b=d[$-1],T=e.matched;if(!b||!T.length)return-1;var C=T.indexOf(b);if(C>-1)return C;var O=T[T.length-2];return $>1&&O&&O===b.parent}),D=computed(function(){return s.value>-1&&_(e.params,n.value.route.params)}),E=computed(function(){return s.value>-1&&s.value===e.matched.length-1&&M(e.params,n.value.route.params)}),h=function(I){var d=n.value.route;return A(I)?r.replace?t.replace(d):t.push(d):Promise.resolve()};return{href:computed(function(){return n.value.href}),route:computed(function(){return n.value.route}),isExactActive:E,isActive:D,navigate:h}}}}]);