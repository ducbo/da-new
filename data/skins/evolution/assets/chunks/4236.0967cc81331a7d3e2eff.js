"use strict";(self.webpackChunk=self.webpackChunk||[]).push([[4236],{"../node_modules/date-fns/esm/formatDistance/index.js":function(S,E,t){t.d(E,{Z:function(){return V}});var n=t("../node_modules/date-fns/esm/_lib/defaultOptions/index.js"),o=t("../node_modules/date-fns/esm/toDate/index.js"),u=t("../node_modules/date-fns/esm/_lib/requiredArgs/index.js");function p(v,f){(0,u.Z)(2,arguments);var c=(0,o.Z)(v),I=(0,o.Z)(f),R=c.getTime()-I.getTime();return R<0?-1:R>0?1:R}function _(v,f){(0,u.Z)(2,arguments);var c=(0,o.Z)(v),I=(0,o.Z)(f),R=c.getFullYear()-I.getFullYear(),C=c.getMonth()-I.getMonth();return R*12+C}function x(v){(0,u.Z)(1,arguments);var f=(0,o.Z)(v);return f.setHours(23,59,59,999),f}function g(v){(0,u.Z)(1,arguments);var f=(0,o.Z)(v),c=f.getMonth();return f.setFullYear(f.getFullYear(),c+1,0),f.setHours(23,59,59,999),f}function i(v){(0,u.Z)(1,arguments);var f=(0,o.Z)(v);return x(f).getTime()===g(f).getTime()}function l(v,f){(0,u.Z)(2,arguments);var c=(0,o.Z)(v),I=(0,o.Z)(f),R=p(c,I),C=Math.abs(_(c,I)),M;if(C<1)M=0;else{c.getMonth()===1&&c.getDate()>27&&c.setDate(30),c.setMonth(c.getMonth()-R*C);var j=p(c,I)===-R;i((0,o.Z)(v))&&C===1&&p(v,I)===1&&(j=!1),M=R*(C-Number(j))}return M===0?0:M}function m(v,f){return(0,u.Z)(2,arguments),(0,o.Z)(v).getTime()-(0,o.Z)(f).getTime()}var a={ceil:Math.ceil,round:Math.round,floor:Math.floor,trunc:function(f){return f<0?Math.ceil(f):Math.floor(f)}},D="trunc";function d(v){return v?a[v]:a[D]}function P(v,f,c){(0,u.Z)(2,arguments);var I=m(v,f)/1e3;return d(c==null?void 0:c.roundingMethod)(I)}var A=t("../node_modules/date-fns/esm/_lib/defaultLocale/index.js");function O(v,f){if(v==null)throw new TypeError("assign requires that input parameter not be null or undefined");for(var c in f)Object.prototype.hasOwnProperty.call(f,c)&&(v[c]=f[c]);return v}function L(v){return O({},v)}var r=t("../node_modules/date-fns/esm/_lib/getTimezoneOffsetInMilliseconds/index.js"),e=1440,s=2520,h=43200,N=86400;function V(v,f,c){var I,R;(0,u.Z)(2,arguments);var C=(0,n.j)(),M=(I=(R=c==null?void 0:c.locale)!==null&&R!==void 0?R:C.locale)!==null&&I!==void 0?I:A.Z;if(!M.formatDistance)throw new RangeError("locale must contain formatDistance property");var j=p(v,f);if(isNaN(j))throw new RangeError("Invalid time value");var y=O(L(c),{addSuffix:Boolean(c==null?void 0:c.addSuffix),comparison:j}),Z,B;j>0?(Z=(0,o.Z)(f),B=(0,o.Z)(v)):(Z=(0,o.Z)(v),B=(0,o.Z)(f));var $=P(B,Z),K=((0,r.Z)(B)-(0,r.Z)(Z))/1e3,T=Math.round(($-K)/60),U;if(T<2)return c!=null&&c.includeSeconds?$<5?M.formatDistance("lessThanXSeconds",5,y):$<10?M.formatDistance("lessThanXSeconds",10,y):$<20?M.formatDistance("lessThanXSeconds",20,y):$<40?M.formatDistance("halfAMinute",0,y):$<60?M.formatDistance("lessThanXMinutes",1,y):M.formatDistance("xMinutes",1,y):T===0?M.formatDistance("lessThanXMinutes",1,y):M.formatDistance("xMinutes",T,y);if(T<45)return M.formatDistance("xMinutes",T,y);if(T<90)return M.formatDistance("aboutXHours",1,y);if(T<e){var F=Math.round(T/60);return M.formatDistance("aboutXHours",F,y)}else{if(T<s)return M.formatDistance("xDays",1,y);if(T<h){var X=Math.round(T/e);return M.formatDistance("xDays",X,y)}else if(T<N)return U=Math.round(T/h),M.formatDistance("aboutXMonths",U,y)}if(U=l(B,Z),U<12){var z=Math.round(T/h);return M.formatDistance("xMonths",z,y)}else{var W=U%12,b=Math.floor(U/12);return W<3?M.formatDistance("aboutXYears",b,y):W<9?M.formatDistance("overXYears",b,y):M.formatDistance("almostXYears",b+1,y)}}},"./js/api/commands/validation/index.js":function(S,E,t){t.d(E,{i9:function(){return P},ty:function(){return D},l7:function(){return m},OE:function(){return d},ub:function(){return r},oH:function(){return g},U5:function(){return i},k_:function(){return x},PR:function(){return a},uo:function(){return L},Jj:function(){return O},rV:function(){return A}});var n=t("./js/api/command/index.js"),o=t("../node_modules/punycode/punycode.es6.js"),u=t("./js/api/commands/converters/index.ts"),p={isValid(s){return typeof s.error=="undefined"},getMessage(s){return(0,u.S8)(s.error||"")}};const _=n.Z.get({url:"/CMD_JSON_VALIDATE",schema:{value:n.Z.REQUIRED_STRING},response:{valid:!0,message:""},mapResponse:{valid:p.isValid,message:p.getMessage}}),x=_.extend({id:"VALIDATE_FORWARDER",params:{type:"forwarder",ignore_system_default:!0}}),g=_.extend({id:"VALIDATE_EMAIL",params:{type:"email",check_mailing_list:!0},schema:{check_exists:{type:Boolean,required:!1,default:!0}}}),i=_.extend({id:"VALIDATE_FTP",params:{type:"ftp"},domain:!0}),l=_.extend({params:{type:"dns"},domain:!0,schema:{record:n.Z.REQUIRED_STRING}}),m=l.extend({id:"VALIDATE_DNS_VALUE",params:{check:"value",name:!0},domain:!0,schema:{value:n.Z.REQUIRED_STRING}}),a=m.extend({id:"VALIDATE_MX_VALUE",params:{record:"MX"},before:({value:s})=>({value:"10",mx_value:s})}),D=l.extend({id:"VALIDATE_DNS_NAME",params:{check:"name",value:!0,mx_value:!0},schema:{name:n.Z.REQUIRED_STRING,value:null}}),d=_.extend({id:"VALIDATE_DATABASE",params:{type:"dbname"}}),P=_.extend({id:"VALIDATE_DATABASE_USER",params:{type:"dbusername"}}),A=_.extend({id:"VALIDATE_USERNAME",params:{type:"username"}}),O=_.extend({id:"VALIDATE_SUBDOMAIN",domain:!0,params:{type:"subdomain"}}),L=_.extend({id:"VALIDATE_PASSWORD",params:{type:"password"}}),r=_.extend({id:"VALIDATE_DOMAIN",params:{type:"domain"},before:({value:s})=>({value:o.ZP.toASCII(s)})}),e=_.extend({id:"VALIDATE_IP_RANGE_LIST",params:{type:"ip_range_list"}})},"./js/api/commands/converters/customItems.ts":function(S,E,t){t.d(E,{CR:function(){return _}});var n=t("../node_modules/ramda/es/index.js"),o=t("./js/api/commands/converters/index.ts"),u=t("./js/api/commands/utils/transduce.ts"),p=t("./js/api/commands/converters/toSelectData.ts");const _=i=>{const l={name:i.name,type:i.type==="listbox"?"select":i.type,label:i.string,description:i.desc||"",value:i.type==="checkbox"?(0,o.sw)(i.checked||"no"):i.value||""};return l.type==="select"?n.BPw(l,(0,p.M1)(i.select||{})):l},x=i=>(0,u.vr)([(0,u.uD)(l=>/^item\d+val$/.test(l)),(0,u.r5)(l=>{const m=l,a=l.replace("val","txt"),D=i[m],d=i[a];return{[D]:d}})],Object.keys(i)),g=(i,l)=>n.qCK(a=>{const D={name:a.name,type:a.type==="listbox"?"select":a.type,description:a.desc||"",value:a.value||"",label:a.string};return a.type==="listbox"?(D.value=a.default,D.options=x(a)):a.type==="checkbox"&&(D.value=a.checked==="yes"),D},n.BPw({name:i}),(0,u.vr)([(0,u.r5)(a=>{const[D,d]=n.Vl2("=",a);return{[D]:d}})]),n.Vl2("&"))(l);E.ZP={fromObject:_,fromString:g}},"./js/api/commands/converters/index.ts":function(S,E,t){t.d(E,{l$:function(){return m.ZP},t0:function(){return n.t0},S8:function(){return n.S8},ql:function(){return n.ql},sw:function(){return n.sw},Qu:function(){return n.Qu},He:function(){return n.He},M1:function(){return l.M1},sf:function(){return D},cc:function(){return i}});var n=t("./js/api/commands/converters/primitive.ts"),o=t("../node_modules/monet/dist/monet.js"),u=t("./js/api/commands/types.ts");const p=d=>typeof d=="object"?o.Either.Right(d):o.Either.Left(new Error("Passed param is not an object")),_=d=>typeof d.usage=="string"?o.Either.Right(d):o.Either.Left(new Error("usage property is required")),x=d=>({usage:(0,n.He)(d.usage),limit:(0,n.Qu)(d.limit)}),g=({usage:d,limit:P})=>{let A=u.H.Normal;const O=Math.floor(d/P*100);return O>=100?A=u.H.OverUsed:O>80&&(A=u.H.AlmostUsed),{usage:d,limit:P,status:A}},i=d=>{const P=o.Either.Right(d).flatMap(p).flatMap(_).map(x).map(g);if(P.isLeft())throw P.left();return P.right()};var l=t("./js/api/commands/converters/toSelectData.ts"),m=t("./js/api/commands/converters/customItems.ts"),a=t("../node_modules/ramda/es/index.js");const D=d=>P=>{const{info:A}=P,O=a.CEd(["info"],P);return{columns:A.columns,rowsCount:Number(A.rows),rows:a.UID(d,a.VO0(O))}}},"./js/api/commands/converters/toSelectData.ts":function(S,E,t){t.d(E,{M1:function(){return g}});var n=t("../node_modules/monet/dist/monet.js"),o=t.n(n),u=t("./js/api/commands/utils/transduce.ts"),p=t("../node_modules/ramda/es/index.js");const _=i=>n.Maybe.Some(i).flatMap(l=>{const m=l.find(a=>a.selected==="yes");return m?n.Maybe.Some(m):n.Maybe.None()}).flatMap(l=>n.Maybe.fromNull(l.value)).orSome(""),x=(0,u.vr)([(0,u.r5)(i=>({[i.value]:i.text}))]),g=i=>{const l=(0,p.VO0)(i);return{value:_(l),options:x(l)}}},"./js/api/commands/types.ts":function(S,E,t){t.d(E,{H:function(){return n}});var n;(function(o){o.Normal="normal",o.AlmostUsed="almost_used",o.OverUsed="overused"})(n||(n={}))},"./js/api/commands/user/domain-pointers.ts":function(S,E,t){t.r(E),t.d(E,{createPointer:function(){return x},deletePointers:function(){return g},getAppPointers:function(){return p},getPointers:function(){return _},setLocal:function(){return i},setRemote:function(){return l}});var n=t("./js/api/command/index.js"),o=t("../node_modules/ramda/es/index.js"),u=t("./js/api/commands/converters/index.ts");const p=o.zGw(o.vgT("domain_pointers"),(0,u.sf)(m=>({domain_pointer:m.domain_pointer,type:m.type,mail:m.local_mail==="yes"?"local":"remote"}))),_=n.Z.get({id:"DOMAIN_POINTERS",url:"/CMD_DOMAIN_POINTER",domain:!0,pagination:!0,mapResponse:p}),x=n.Z.post({url:"/CMD_DOMAIN_POINTER",params:{action:"add"},domain:!0,schema:{from:n.Z.REQUIRED_STRING,alias:n.Z.REQUIRED_BOOL}}),g=n.Z.select({url:"/CMD_DOMAIN_POINTER",params:{action:"delete"},domain:!0}),i=g.extend({params:{local_mail:!0}}),l=g.extend({params:{remote_mail:!0}})},"./js/api/commands/utils/transduce.ts":function(S,E,t){t.d(E,{Re:function(){return p},r5:function(){return o},uD:function(){return u},vr:function(){return l},zh:function(){return g}});var n=t("../node_modules/ramda/es/index.js");const o=m=>a=>(D,d)=>{const P=m(d);return a(D,P)},u=m=>a=>(D,d)=>m(d)?a(D,d):D,p=(m,a)=>(m.push(a),m),_=(m,a)=>n.BPw(m,a),x=(m,a,D,d)=>{const P=n.qCK(...D);return d.reduce(P(a),m)},g=n.WAo(x),i=g([],p),l=g({},_)},"./js/composables/dateFilter.ts":function(S,E,t){t.d(E,{W:function(){return _},f:function(){return u.f}});var n=t("../node_modules/ramda/es/index.js"),o=t("../node_modules/date-fns/esm/format/index.js"),u=t("./js/modules/date-formats.ts"),p=t("./js/modules/customizations/date-formats/default.ts");const _=n.WAo((x,g)=>{if(g)try{return(0,o.Z)(g,u.f.value[x])}catch(i){return console.warn(`Given ${x} format is incorrect:
${i.message}`),(0,o.Z)(g,p.d[x])}return""})},"./js/composables/filters.ts":function(S,E,t){t.d(E,{Q0:function(){return P},aS:function(){return O},d5:function(){return A},eB:function(){return a},hT:function(){return l},kC:function(){return i},n9:function(){return d},zM:function(){return m}});var n=t("../node_modules/date-fns/esm/formatDistance/index.js"),o=t("../node_modules/punycode/punycode.es6.js"),u=t("./js/composables/dateFilter.ts"),p=t("./js/composables/gettext.ts");const{$gettext:_,$ngettext:x,$gettextInterpolate:g}=(0,p.Z)(),i=r=>{var e;return r?((e=r.at(0))===null||e===void 0?void 0:e.toUpperCase())+r.slice(1):""},l=(r,e="datetime")=>(0,u.W)(e,r),m=r=>(0,n.Z)(r,new Date),a=(r,e=1024)=>{const s=Number(r);if(!s)return"0 B";const h=["B","KB","MB","GB","TB","PB","EB","ZB","YB"],N=Math.floor(Math.log(s)/Math.log(e));return`${parseFloat((s/e**N).toFixed(2))} ${h[N]}`},D=r=>{try{return(0,o.xX)(r)}catch(e){return r}},d=r=>(0,o.xX)(r),P=r=>{if(!r||!r.includes("@"))return r;const[e,s]=r.split("@");return[e,D(s)].join("@")},A=r=>{if(r<60)return _("less than a minute");const e=Math.floor(r/60)%60,s=Math.floor(r/3600)%24,h=Math.floor(r/(3600*24)),N=[h?x("%{days} day","%{days} days",h):null,s?x("%{hours} hour","%{hours} hours",s):null,e?x("%{minutes} minute","%{minutes} minutes",e):null].filter(Boolean).join(", ");return g(N,{days:h,hours:s,minutes:e})},O=(r,e)=>r.length<=e?r:`${r.substring(0,e)}...`,L=()=>({capitalize:i,date:l,distanceFromNow:m,humanReadableSize:a,p6eUnicode:d,p6eUnicodeEmail:P,formatUptime:A,truncateString:O})},"./js/pages/user/domain-pointers.vue":function(S,E,t){t.r(E),t.d(E,{default:function(){return L}});var n=function(){var e=this,s=e._self._c;return s("app-page",{attrs:{actions:[{handler:e.$dialog("CREATE_DOMAIN_POINTER_DIALOG").open,label:e.$gettext("Create Domain Pointer"),icon:"#plus-fill",visible:e.pointersCount<=e.$_session.usage.domainPointers.limit,theme:"safe"}]},scopedSlots:e._u([{key:"details",fn:function(){return[s("ui-infobar-item",{attrs:{title:e.$gettext("Details")}},[s("ui-infobar-stats",e._b({},"ui-infobar-stats",{title:e.$gettext("Pointers"),usage:e.pointersCount,limit:e.limit},!1))],1)]},proxy:!0},{key:"default",fn:function(){return[s("app-page-section",[s("ui-api-table",e._b({ref:"table",attrs:{editable:!1,"vertical-layout":e.clientStore.isPhone},on:{"action:del":function(h){e.$dialog("DELETE_DOMAIN_POINTERS").open()},"action:setLocal":e.setLocal,"action:setRemote":e.setRemote},scopedSlots:e._u([{key:"col:domain_pointer",fn:function({domain_pointer:h}){return[e._v(`
                    `+e._s(e.p6eUnicode(h))+`
                `)]}},{key:"col:type",fn:function({type:h}){return[s("ui-badge",{attrs:{theme:"primary",size:"small"}},[s("span",{domProps:{textContent:e._s(h==="alias"?e.$gettext("Alias"):e.$gettext("Pointer"))}})])]}},{key:"col:mail",fn:function({mail:h}){return[s("span",{domProps:{textContent:e._s(h==="local"?e.$gettext("Yes"):e.$gettext("No"))}})]}},e.dnsControl?{key:"col:dns",fn:function({domain_pointer:h}){return[s("ui-link",{attrs:{name:"user/dns",query:{pointer:h}}},[s("span",{domProps:{textContent:e._s(e.$_useStore("user").mode==="user"?e.$gettext("View"):e.$gettext("Manage"))}})])]}}:null],null,!0),model:{value:e.select,callback:function(h){e.select=h},expression:"select"}},"ui-api-table",{command:e.$commands.getPointers,rowID:"domain_pointer",columns:{domain_pointer:e.$gettext("Domain Pointer"),type:e.$gettext("Type"),mail:e.$gettext("Local Mail"),dns:e.$gettext("DNS")},actions:{del:e.$gettext("Delete"),setLocal:e.$gettext("Set Local Mail"),setRemote:e.$gettext("Set Remote Mail")}},!1))],1),e._v(" "),s("create-domain-pointer-dialog",{on:{create:e.$reloadApiTable}}),e._v(" "),s("ui-dialog-delete-items",{attrs:{id:"DELETE_DOMAIN_POINTERS",subject:e.$ngettext("Domain Pointer","Domain Pointers",e.select.length)},on:{"click:confirm":e.deletePointers}})]},proxy:!0}])})},o=[],u=t("./js/stores/index.ts"),p=t("./js/api/commands/user/domain-pointers.ts"),_=function(){var e=this,s=e._self._c;return s("ui-dialog",{attrs:{id:"CREATE_DOMAIN_POINTER_DIALOG",theme:"safe",title:e.$gettext("Add New Domain Pointer")},scopedSlots:e._u([{key:"content",fn:function(){return[s("ui-form-element",{attrs:{group:"domainPointer",validators:{required:!0,api:e.$commands.validateDomain},vertical:""},scopedSlots:e._u([{key:"title",fn:function(){return[e._v(e._s(e.$gettext("Source Domain")))]},proxy:!0},{key:"tooltip",fn:function(){return[e._v(`
                `+e._s(e.$gettext("eg. sourcedomain.com"))+`
            `)]},proxy:!0},{key:"content",fn:function(){return[s("input-text",{attrs:{prefix:"http://www."},model:{value:e.from,callback:function(h){e.from=h},expression:"from"}})]},proxy:!0}])}),e._v(" "),s("ui-form-element",{attrs:{vertical:""},scopedSlots:e._u([{key:"title",fn:function(){return[e._v(e._s(e.$gettext("Target Domain")))]},proxy:!0},{key:"content",fn:function(){return[s("input-text",{attrs:{disabled:"",value:e.$domainUnicode}})]},proxy:!0}])}),e._v(" "),s("ui-form-element",{attrs:{vertical:""},scopedSlots:e._u([{key:"content",fn:function(){return[s("input-checkbox",{model:{value:e.alias,callback:function(h){e.alias=h},expression:"alias"}},[s("span",{domProps:{textContent:e._s(e.$gettext("Create as an Alias"))}})])]},proxy:!0}])})]},proxy:!0},{key:"buttons",fn:function(){return[s("ui-button",{attrs:{theme:"safe","validate-group":"domainPointer"},on:{click:e.createDomainPointer}},[s("span",{domProps:{textContent:e._s(e.$gettext("Create"))}})])]},proxy:!0}])})},x=[],g=t("./js/api/commands/validation/index.js"),i={data:()=>({from:"",alias:!0}),commands:{validateDomain:g.ub},methods:{async createDomainPointer(){const r=this.$p6e.toA(this.from);r!==this.from&&this.$notifications.info({title:this.$gettext("Source domain name punycoded"),content:this.$gettext("Source domain name has been automatically converted to punycode format. Punycode is used to encode internationalized domain names (IDN) by converting Unicode characters to ASCII.")}),await p.createPointer({from:r,alias:this.alias})&&(Object.assign(this.$data,this.$options.data.apply(this)),this.$emit("create"))}}},l=i,m=t("../node_modules/vue-loader/lib/runtime/componentNormalizer.js"),a=(0,m.Z)(l,_,x,!1,null,null,null),D=a.exports,d=t("./js/composables/filters.ts"),P={preload:p.getPointers,components:{CreateDomainPointerDialog:D},commands:p,api:[{command:p.getPointers,bind:"pointers"}],data:()=>({select:[]}),computed:{dnsControl(){return this.$_flags.user.dnsControl},limit(){return this.$_session.usage.domainPointers.limit},pointersCount(){return this.$api.pointers.rowsCount},...(0,u.Kc)(["client"])},watch:{$domain(){p.getPointers()}},methods:{p6eUnicode:d.n9,submitCommand(r){r({select:this.select}).then(this.$reloadApiTable)},deletePointers(){this.submitCommand(p.deletePointers)},setRemote(){this.submitCommand(p.setRemote)},setLocal(){this.submitCommand(p.setLocal)}}},A=P,O=(0,m.Z)(A,n,o,!1,null,null,null),L=O.exports}}]);