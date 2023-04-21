"use strict";(self.webpackChunk=self.webpackChunk||[]).push([[3645],{"../node_modules/date-fns/esm/formatDistance/index.js":function(A,D,a){a.d(D,{Z:function(){return U}});var g=a("../node_modules/date-fns/esm/_lib/defaultOptions/index.js"),n=a("../node_modules/date-fns/esm/toDate/index.js"),m=a("../node_modules/date-fns/esm/_lib/requiredArgs/index.js");function p(l,u){(0,m.Z)(2,arguments);var i=(0,n.Z)(l),x=(0,n.Z)(u),M=i.getTime()-x.getTime();return M<0?-1:M>0?1:M}function r(l,u){(0,m.Z)(2,arguments);var i=(0,n.Z)(l),x=(0,n.Z)(u),M=i.getFullYear()-x.getFullYear(),S=i.getMonth()-x.getMonth();return M*12+S}function v(l){(0,m.Z)(1,arguments);var u=(0,n.Z)(l);return u.setHours(23,59,59,999),u}function y(l){(0,m.Z)(1,arguments);var u=(0,n.Z)(l),i=u.getMonth();return u.setFullYear(u.getFullYear(),i+1,0),u.setHours(23,59,59,999),u}function T(l){(0,m.Z)(1,arguments);var u=(0,n.Z)(l);return v(u).getTime()===y(u).getTime()}function R(l,u){(0,m.Z)(2,arguments);var i=(0,n.Z)(l),x=(0,n.Z)(u),M=p(i,x),S=Math.abs(r(i,x)),d;if(S<1)d=0;else{i.getMonth()===1&&i.getDate()>27&&i.setDate(30),i.setMonth(i.getMonth()-M*S);var Z=p(i,x)===-M;T((0,n.Z)(l))&&S===1&&p(l,x)===1&&(Z=!1),d=M*(S-Number(Z))}return d===0?0:d}function O(l,u){return(0,m.Z)(2,arguments),(0,n.Z)(l).getTime()-(0,n.Z)(u).getTime()}var b={ceil:Math.ceil,round:Math.round,floor:Math.floor,trunc:function(u){return u<0?Math.ceil(u):Math.floor(u)}},P="trunc";function s(l){return l?b[l]:b[P]}function e(l,u,i){(0,m.Z)(2,arguments);var x=O(l,u)/1e3;return s(i==null?void 0:i.roundingMethod)(x)}var t=a("../node_modules/date-fns/esm/_lib/defaultLocale/index.js");function c(l,u){if(l==null)throw new TypeError("assign requires that input parameter not be null or undefined");for(var i in u)Object.prototype.hasOwnProperty.call(u,i)&&(l[i]=u[i]);return l}function I(l){return c({},l)}var o=a("../node_modules/date-fns/esm/_lib/getTimezoneOffsetInMilliseconds/index.js"),f=1440,E=2520,$=43200,C=86400;function U(l,u,i){var x,M;(0,m.Z)(2,arguments);var S=(0,g.j)(),d=(x=(M=i==null?void 0:i.locale)!==null&&M!==void 0?M:S.locale)!==null&&x!==void 0?x:t.Z;if(!d.formatDistance)throw new RangeError("locale must contain formatDistance property");var Z=p(l,u);if(isNaN(Z))throw new RangeError("Invalid time value");var h=c(I(i),{addSuffix:Boolean(i==null?void 0:i.addSuffix),comparison:Z}),N,L;Z>0?(N=(0,n.Z)(u),L=(0,n.Z)(l)):(N=(0,n.Z)(l),L=(0,n.Z)(u));var j=e(L,N),X=((0,o.Z)(L)-(0,o.Z)(N))/1e3,_=Math.round((j-X)/60),k;if(_<2)return i!=null&&i.includeSeconds?j<5?d.formatDistance("lessThanXSeconds",5,h):j<10?d.formatDistance("lessThanXSeconds",10,h):j<20?d.formatDistance("lessThanXSeconds",20,h):j<40?d.formatDistance("halfAMinute",0,h):j<60?d.formatDistance("lessThanXMinutes",1,h):d.formatDistance("xMinutes",1,h):_===0?d.formatDistance("lessThanXMinutes",1,h):d.formatDistance("xMinutes",_,h);if(_<45)return d.formatDistance("xMinutes",_,h);if(_<90)return d.formatDistance("aboutXHours",1,h);if(_<f){var w=Math.round(_/60);return d.formatDistance("aboutXHours",w,h)}else{if(_<E)return d.formatDistance("xDays",1,h);if(_<$){var Y=Math.round(_/f);return d.formatDistance("xDays",Y,h)}else if(_<C)return k=Math.round(_/$),d.formatDistance("aboutXMonths",k,h)}if(k=R(L,N),k<12){var F=Math.round(_/$);return d.formatDistance("xMonths",F,h)}else{var W=k%12,B=Math.floor(k/12);return W<3?d.formatDistance("aboutXYears",B,h):W<9?d.formatDistance("overXYears",B,h):d.formatDistance("almostXYears",B+1,h)}}},"./js/vue-globals/helpers/time-distance.js":function(A,D,a){var g=a("../node_modules/date-fns/esm/formatDistance/index.js"),n=a("./js/gettext.js");const m={formatDistance:(p,r)=>{const v={lessThanXSeconds:(0,n.$ngettext)("less than a second","less than %{ count } seconds",r),xSeconds:(0,n.$ngettext)("%{ count } second","%{ count } seconds",r),halfAMinute:(0,n.$gettext)("half a minute"),lessThanXMinutes:(0,n.$ngettext)("less than a minute","less than %{ count } minutes",r),xMinutes:(0,n.$ngettext)("%{ count } minute","%{ count } minutes",r),aboutXHours:(0,n.$ngettext)("about %{ count } hour","about %{ count } hours",r),xHours:(0,n.$ngettext)("%{ count } hour","%{ count } hours",r),xDays:(0,n.$ngettext)("%{ count } day","%{ count } days",r),aboutXWeeks:(0,n.$ngettext)("about %{ count } week","about %{ count } weeks",r),xWeeks:(0,n.$ngettext)("%{ count } week","%{ count } weeks",r),aboutXMonths:(0,n.$ngettext)("about %{ count } month","about %{ count } months",r),xMonths:(0,n.$ngettext)("%{ count } month","%{ count } months",r),aboutXYears:(0,n.$ngettext)("about %{ count } year","about %{ count } years",r),xYears:(0,n.$ngettext)("%{ count } year","%{ count } years",r),overXYears:(0,n.$ngettext)("over %{ count } year","over %{ count } years",r),almostXYears:(0,n.$ngettext)("almost %{ count } year","almost %{ count } years",r)};return(0,n.$gettextInterpolate)(v[p],{count:r})}};D.Z=(p,r)=>(0,g.Z)(r,p,{locale:m})},"./js/composables/dateFilter.ts":function(A,D,a){a.d(D,{W:function(){return r},f:function(){return m.f}});var g=a("../node_modules/ramda/es/index.js"),n=a("../node_modules/date-fns/esm/format/index.js"),m=a("./js/modules/date-formats.ts"),p=a("./js/modules/customizations/date-formats/default.ts");const r=g.WAo((v,y)=>{if(y)try{return(0,n.Z)(y,m.f.value[v])}catch(T){return console.warn(`Given ${v} format is incorrect:
${T.message}`),(0,n.Z)(y,p.d[v])}return""})},"./js/composables/filters.ts":function(A,D,a){a.d(D,{Q0:function(){return e},aS:function(){return c},d5:function(){return t},eB:function(){return b},hT:function(){return R},kC:function(){return T},n9:function(){return s},zM:function(){return O}});var g=a("../node_modules/date-fns/esm/formatDistance/index.js"),n=a("../node_modules/punycode/punycode.es6.js"),m=a("./js/composables/dateFilter.ts"),p=a("./js/composables/gettext.ts");const{$gettext:r,$ngettext:v,$gettextInterpolate:y}=(0,p.Z)(),T=o=>{var f;return o?((f=o.at(0))===null||f===void 0?void 0:f.toUpperCase())+o.slice(1):""},R=(o,f="datetime")=>(0,m.W)(f,o),O=o=>(0,g.Z)(o,new Date),b=(o,f=1024)=>{const E=Number(o);if(!E)return"0 B";const $=["B","KB","MB","GB","TB","PB","EB","ZB","YB"],C=Math.floor(Math.log(E)/Math.log(f));return`${parseFloat((E/f**C).toFixed(2))} ${$[C]}`},P=o=>{try{return(0,n.xX)(o)}catch(f){return o}},s=o=>(0,n.xX)(o),e=o=>{if(!o||!o.includes("@"))return o;const[f,E]=o.split("@");return[f,P(E)].join("@")},t=o=>{if(o<60)return r("less than a minute");const f=Math.floor(o/60)%60,E=Math.floor(o/3600)%24,$=Math.floor(o/(3600*24)),C=[$?v("%{days} day","%{days} days",$):null,E?v("%{hours} hour","%{hours} hours",E):null,f?v("%{minutes} minute","%{minutes} minutes",f):null].filter(Boolean).join(", ");return y(C,{days:$,hours:E,minutes:f})},c=(o,f)=>o.length<=f?o:`${o.substring(0,f)}...`,I=()=>({capitalize:T,date:R,distanceFromNow:O,humanReadableSize:b,p6eUnicode:s,p6eUnicodeEmail:e,formatUptime:t,truncateString:c})},"./js/openapi/cpanel.ts":function(A,D,a){a.d(D,{Ak:function(){return y},C2:function(){return T},Di:function(){return v},_5:function(){return O},yS:function(){return P}});var g=a("./js/api/openapi/index.ts"),n=a("../node_modules/runtypes/lib/index.js"),m=a.n(n),p=a("./js/openapi/web.types.ts");const r=(0,g.$d)(),v=g.an.Default(async(s,e)=>{const{data:t}=await r.post("/api/cpanel-import/check-remote",s,e);return t.status==="success"&&p.Tf.guard(t.data)===!1?r.failure({type:"INVALID_RESPONSE",response:t.data}):t}),y=g.an.Default(async s=>{const{data:e}=await r.get("/api/cpanel-import/tasks",s);return e.status==="success"&&n.Array(p.hr).guard(e.data)===!1?r.failure({type:"INVALID_RESPONSE",response:e.data}):e}),T=g.an.Default(async(s,e)=>{const{data:t}=await r.post("/api/cpanel-import/tasks/start",s,e);return t.status==="success"&&n.Array(p.hr).guard(t.data)===!1?r.failure({type:"INVALID_RESPONSE",response:t.data}):t}),R=g.an.Default(async(s,e)=>{const{data:t}=await r.get(`/api/cpanel-import/tasks/${s}`,e);return t.status==="success"&&p.hr.guard(t.data)===!1?r.failure({type:"INVALID_RESPONSE",response:t.data}):t}),O=g.an.Default(async(s,e)=>{const{data:t}=await r.delete(`/api/cpanel-import/tasks/${s}`,e);return t}),b=async(s,e)=>{const{data:t}=await r.get(`/api/cpanel-import/tasks/${s}/log`,e);return t.status==="success"&&rt.Array(web.rtCpanelImportTaskLog).guard(t.data)===!1?r.failure({type:"INVALID_RESPONSE",response:t.data}):t};class P extends g.MF{constructor(){super(...arguments),this.streamType=g.MF.JSON_STREAM,this.validator=p.J0}open(e,t){return super.connect(`/api/cpanel-import/tasks/${e}/log-sse`,t||{})}}},"./js/pages/reseller/cpanel/index.vue":function(A,D,a){a.r(D),a.d(D,{default:function(){return P}});var g=function(){var e=this,t=e._self._c;return t("app-page",{attrs:{id:"cpanel-imports",actions:[{label:e.$gettext("New Import"),handler:()=>e.$router.push("/reseller/cpanel-import/start"),icon:"#plus-fill"}]},scopedSlots:e._u([{key:"default",fn:function(){return[t("app-page-section",[t("ui-r-table",{attrs:{rows:e.tasks,columns:[{id:"account",label:e.$gettext("Account")},{id:"stage",label:e.$gettext("Stage")},{id:"remote",label:e.$gettext("Remote Server")},{id:"startTime",label:e.$gettext("Start Time")},{id:"duration",label:e.$gettext("Duration")},{id:"ignore",label:e.$gettext("Ignore Errors")},{id:"replace",label:e.$gettext("Replace Users")},{id:"log",label:e.$gettext("Log")},{id:"cancel",label:e.$gettext("Cancel"),visible:e.visibleCancel}],sort:{key:"startTime",order:"DESC"},"disable-pagination":"","is-checkable":!1},scopedSlots:e._u([{key:"buttons:before:end",fn:function(){return[t("ui-refresh-timer",{attrs:{options:{30:e.$gettext("30 seconds"),60:e.$gettext("1 minute"),120:e.$gettext("2 minutes"),300:e.$gettext("5 minutes")},"initial-delay":"60","on-refresh":e.getCpanelTasks}})]},proxy:!0},{key:"col:startTime",fn:function({startTime:c}){return[e._v(`
                    `+e._s(e.date(c,"datetime"))+`
                `)]}},{key:"col:stopTime",fn:function({stopTime:c}){return[e._v(`
                    `+e._s(e.date(c,"datetime"))+`
                `)]}},{key:"col:stage",fn:function({id:c,stage:I,error:o}){return[o?t("ui-tooltip",{key:`${c}-error`,staticStyle:{display:"inline-block"},attrs:{theme:"danger"},scopedSlots:e._u([{key:"trigger",fn:function(){return[t("ui-badge",{attrs:{theme:"danger"},scopedSlots:e._u([{key:"icon",fn:function(){return[t("ui-icon",{attrs:{id:"exclamation-triangle",size:16,theme:"danger"}})]},proxy:!0}],null,!0)})]},proxy:!0}],null,!0)},[e._v(" "),t("span",{domProps:{textContent:e._s(e.stages[I])}}),e._v(" "),t("span",{domProps:{textContent:e._s(o)}})]):I!=="done"?t("ui-badge",{attrs:{theme:"primary"},scopedSlots:e._u([{key:"icon",fn:function(){return[t("ui-loader-icon",{attrs:{size:16}})]},proxy:!0}],null,!0)},[e._v(" "),t("span",{domProps:{textContent:e._s(e.stages[I])}})]):t("ui-badge",{attrs:{theme:"safe"},scopedSlots:e._u([{key:"icon",fn:function(){return[t("ui-icon",{attrs:{id:"check-mark",size:16,theme:"safe"}})]},proxy:!0}],null,!0)},[e._v(" "),t("span",{domProps:{textContent:e._s(e.stages[I])}})])]}},{key:"col:ignore",fn:function({options:c}){return[t("span",{domProps:{textContent:e._s(c.ignore?e.$gettext("Yes"):e.$gettext("No"))}})]}},{key:"col:replace",fn:function({options:c}){return[t("span",{domProps:{textContent:e._s(c.replace?e.$gettext("Yes"):e.$gettext("No"))}})]}},{key:"col:log",fn:function({id:c}){return[t("ui-link",{directives:[{name:"margin",rawName:"v-margin:left",value:1,expression:"1",arg:"left"}],attrs:{name:"reseller/cpanel/logs",params:{id:c}}},[t("ui-icon",{attrs:{id:"log",theme:"primary"}})],1)]}},{key:"col:duration",fn:function({duration:c}){return[e._v(`
                    `+e._s(c)+`
                `)]}},{key:"col:cancel",fn:function({item:c}){return[c.stage==="pending"&&!c.error?t("ui-button",{attrs:{title:e.$gettext("Stop Task")},on:{click:function(I){return e.stopTask(c)}},scopedSlots:e._u([{key:"icon",fn:function(){return[t("ui-icon",{attrs:{id:"cancel",theme:"danger"}})]},proxy:!0}],null,!0)}):e._e()]}}],null,!0)})],1)]},proxy:!0}])})},n=[],m=a("./js/openapi/cpanel.ts"),p=a("./js/vue-globals/helpers/time-distance.js"),r=a("./js/composables/filters.ts"),v=a("./js/composables/index.ts");const y=(0,v.Lu)({});var T={name:"CpanelImportList",data(){return{loading:!1,rawTasks:[]}},computed:{stages(){return{pending:this.$gettext("Pending"),backup:this.$gettext("Backup"),download:this.$gettext("Download"),convert:this.$gettext("Convert"),restore:this.$gettext("Restore"),done:this.$gettext("Done")}},visibleCancel(){return this.tasks.some(s=>s.stage==="pending"&&!s.error)},tasks(){return this.rawTasks.map(s=>({account:s.account,remote:`${s.remoteUser}@${s.remoteHost}:${s.remotePort}`,id:s.id,stage:s.stage,startTime:new Date(s.startTime),duration:this.formatDuration(s),error:s.error,options:{replace:s.replaceExistingUser,ignore:s.ignoreConvertErrors}}))}},created(){this.getCpanelTasks()},methods:{date:r.hT,async getCpanelTasks(){this.loading=!0;const{data:s,error:e}=await(0,m.Ak)();if(this.loading=!1,e){y(e);return}if(!s){this.tasks=[];return}this.rawTasks=s},async stopTask(s){const{error:e}=await(0,m._5)(s.id);if(e){y(e);return}this.getCpanelTasks()},formatDuration(s){const e=new Date(s.startTime),t=new Date(s.stopTime);return t.getFullYear()===1?this.$gettext("In progress"):(0,p.Z)(e,t)}}},R=T,O=a("../node_modules/vue-loader/lib/runtime/componentNormalizer.js"),b=(0,O.Z)(R,g,n,!1,null,null,null),P=b.exports}}]);