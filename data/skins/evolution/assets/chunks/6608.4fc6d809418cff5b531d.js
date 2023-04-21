"use strict";(self.webpackChunk=self.webpackChunk||[]).push([[6608],{"../node_modules/date-fns/esm/formatDistance/index.js":function(N,h,n){n.d(h,{Z:function(){return B}});var C=n("../node_modules/date-fns/esm/_lib/defaultOptions/index.js"),l=n("../node_modules/date-fns/esm/toDate/index.js"),c=n("../node_modules/date-fns/esm/_lib/requiredArgs/index.js");function x(i,r){(0,c.Z)(2,arguments);var o=(0,l.Z)(i),m=(0,l.Z)(r),g=o.getTime()-m.getTime();return g<0?-1:g>0?1:g}function P(i,r){(0,c.Z)(2,arguments);var o=(0,l.Z)(i),m=(0,l.Z)(r),g=o.getFullYear()-m.getFullYear(),$=o.getMonth()-m.getMonth();return g*12+$}function u(i){(0,c.Z)(1,arguments);var r=(0,l.Z)(i);return r.setHours(23,59,59,999),r}function f(i){(0,c.Z)(1,arguments);var r=(0,l.Z)(i),o=r.getMonth();return r.setFullYear(r.getFullYear(),o+1,0),r.setHours(23,59,59,999),r}function M(i){(0,c.Z)(1,arguments);var r=(0,l.Z)(i);return u(r).getTime()===f(r).getTime()}function U(i,r){(0,c.Z)(2,arguments);var o=(0,l.Z)(i),m=(0,l.Z)(r),g=x(o,m),$=Math.abs(P(o,m)),d;if($<1)d=0;else{o.getMonth()===1&&o.getDate()>27&&o.setDate(30),o.setMonth(o.getMonth()-g*$);var v=x(o,m)===-g;M((0,l.Z)(i))&&$===1&&x(i,m)===1&&(v=!1),d=g*($-Number(v))}return d===0?0:d}function Z(i,r){return(0,c.Z)(2,arguments),(0,l.Z)(i).getTime()-(0,l.Z)(r).getTime()}var T={ceil:Math.ceil,round:Math.round,floor:Math.floor,trunc:function(r){return r<0?Math.ceil(r):Math.floor(r)}},A="trunc";function j(i){return i?T[i]:T[A]}function b(i,r,o){(0,c.Z)(2,arguments);var m=Z(i,r)/1e3;return j(o==null?void 0:o.roundingMethod)(m)}var I=n("../node_modules/date-fns/esm/_lib/defaultLocale/index.js");function S(i,r){if(i==null)throw new TypeError("assign requires that input parameter not be null or undefined");for(var o in r)Object.prototype.hasOwnProperty.call(r,o)&&(i[o]=r[o]);return i}function F(i){return S({},i)}var a=n("../node_modules/date-fns/esm/_lib/getTimezoneOffsetInMilliseconds/index.js"),_=1440,D=2520,y=43200,L=86400;function B(i,r,o){var m,g;(0,c.Z)(2,arguments);var $=(0,C.j)(),d=(m=(g=o==null?void 0:o.locale)!==null&&g!==void 0?g:$.locale)!==null&&m!==void 0?m:I.Z;if(!d.formatDistance)throw new RangeError("locale must contain formatDistance property");var v=x(i,r);if(isNaN(v))throw new RangeError("Invalid time value");var t=S(F(o),{addSuffix:Boolean(o==null?void 0:o.addSuffix),comparison:v}),e,s;v>0?(e=(0,l.Z)(r),s=(0,l.Z)(i)):(e=(0,l.Z)(i),s=(0,l.Z)(r));var E=b(s,e),z=((0,a.Z)(s)-(0,a.Z)(e))/1e3,p=Math.round((E-z)/60),O;if(p<2)return o!=null&&o.includeSeconds?E<5?d.formatDistance("lessThanXSeconds",5,t):E<10?d.formatDistance("lessThanXSeconds",10,t):E<20?d.formatDistance("lessThanXSeconds",20,t):E<40?d.formatDistance("halfAMinute",0,t):E<60?d.formatDistance("lessThanXMinutes",1,t):d.formatDistance("xMinutes",1,t):p===0?d.formatDistance("lessThanXMinutes",1,t):d.formatDistance("xMinutes",p,t);if(p<45)return d.formatDistance("xMinutes",p,t);if(p<90)return d.formatDistance("aboutXHours",1,t);if(p<_){var R=Math.round(p/60);return d.formatDistance("aboutXHours",R,t)}else{if(p<D)return d.formatDistance("xDays",1,t);if(p<y){var W=Math.round(p/_);return d.formatDistance("xDays",W,t)}else if(p<L)return O=Math.round(p/y),d.formatDistance("aboutXMonths",O,t)}if(O=U(s,e),O<12){var V=Math.round(p/y);return d.formatDistance("xMonths",V,t)}else{var Y=O%12,X=Math.floor(O/12);return Y<3?d.formatDistance("aboutXYears",X,t):Y<9?d.formatDistance("overXYears",X,t):d.formatDistance("almostXYears",X+1,t)}}},"./js/composables/dateFilter.ts":function(N,h,n){n.d(h,{W:function(){return P},f:function(){return c.f}});var C=n("../node_modules/ramda/es/index.js"),l=n("../node_modules/date-fns/esm/format/index.js"),c=n("./js/modules/date-formats.ts"),x=n("./js/modules/customizations/date-formats/default.ts");const P=C.WAo((u,f)=>{if(f)try{return(0,l.Z)(f,c.f.value[u])}catch(M){return console.warn(`Given ${u} format is incorrect:
${M.message}`),(0,l.Z)(f,x.d[u])}return""})},"./js/composables/filters.ts":function(N,h,n){n.d(h,{Q0:function(){return b},aS:function(){return S},d5:function(){return I},eB:function(){return T},hT:function(){return U},kC:function(){return M},n9:function(){return j},zM:function(){return Z}});var C=n("../node_modules/date-fns/esm/formatDistance/index.js"),l=n("../node_modules/punycode/punycode.es6.js"),c=n("./js/composables/dateFilter.ts"),x=n("./js/composables/gettext.ts");const{$gettext:P,$ngettext:u,$gettextInterpolate:f}=(0,x.Z)(),M=a=>{var _;return a?((_=a.at(0))===null||_===void 0?void 0:_.toUpperCase())+a.slice(1):""},U=(a,_="datetime")=>(0,c.W)(_,a),Z=a=>(0,C.Z)(a,new Date),T=(a,_=1024)=>{const D=Number(a);if(!D)return"0 B";const y=["B","KB","MB","GB","TB","PB","EB","ZB","YB"],L=Math.floor(Math.log(D)/Math.log(_));return`${parseFloat((D/_**L).toFixed(2))} ${y[L]}`},A=a=>{try{return(0,l.xX)(a)}catch(_){return a}},j=a=>(0,l.xX)(a),b=a=>{if(!a||!a.includes("@"))return a;const[_,D]=a.split("@");return[_,A(D)].join("@")},I=a=>{if(a<60)return P("less than a minute");const _=Math.floor(a/60)%60,D=Math.floor(a/3600)%24,y=Math.floor(a/(3600*24)),L=[y?u("%{days} day","%{days} days",y):null,D?u("%{hours} hour","%{hours} hours",D):null,_?u("%{minutes} minute","%{minutes} minutes",_):null].filter(Boolean).join(", ");return f(L,{days:y,hours:D,minutes:_})},S=(a,_)=>a.length<=_?a:`${a.substring(0,_)}...`,F=()=>({capitalize:M,date:U,distanceFromNow:Z,humanReadableSize:T,p6eUnicode:j,p6eUnicodeEmail:b,formatUptime:I,truncateString:S})},"./js/composables/useDataStore.ts":function(N,h,n){n.d(h,{a:function(){return x}});var C=n("./js/api/openapi/decorators/data-store-decorator.ts"),l=n("../node_modules/vue/dist/vue.common.prod.js"),c=n.n(l);const x=P=>{const u=(0,l.ref)(null);return{data:u,request:(0,C.i)(u,P)}}},"./js/openapi/license.ts":function(N,h,n){n.d(h,{l:function(){return x},o:function(){return P}});var C=n("./js/api/openapi/index.ts"),l=n("./js/openapi/web.types.ts");const c=(0,C.$d)(),x=C.an.Default(async u=>{const{data:f}=await c.get("/api/license",u);return f.status==="success"&&l.IM.guard(f.data)===!1?c.failure({type:"INVALID_RESPONSE",response:f.data}):f}),P=C.an.Default(async u=>{const{data:f}=await c.get("/api/license/proof",u);return f.status==="success"&&l.kX.guard(f.data)===!1?c.failure({type:"INVALID_RESPONSE",response:f.data}):f})},"./js/pages/admin/license/index.vue":function(N,h,n){n.r(h),n.d(h,{default:function(){return d}});var C=function(){var t=this,e=t._self._c,s=t._self._setupProxy;return e("app-page",{scopedSlots:t._u([{key:"default",fn:function(){return[e("app-page-section",{scopedSlots:t._u([{key:"footer:buttons",fn:function(){return[e("ui-button",{attrs:{theme:"safe"},on:{click:s.proofLicense}},[e("span",{domProps:{textContent:t._s(s.$gettext("Proof License"))}})])]},proxy:!0}])},[e("table",{staticClass:"table-elem"},[e("tbody",[e("tr",[e("td",{staticClass:"txt:bold",domProps:{textContent:t._s(s.$gettext("Name"))}}),t._v(" "),e("td",[t._v(`
                            `+t._s(s.license.name)+`
                        `)])]),t._v(" "),e("tr",[e("td",{staticClass:"txt:bold",domProps:{textContent:t._s(s.$gettext("License ID (LID)"))}}),t._v(" "),e("td",[t._v(`
                            `+t._s(s.license.lid)+`
                            `),s.license.limits.trial?e("ui-badge",{attrs:{theme:"danger",size:"small",label:"Trial"}}):t._e()],1)]),t._v(" "),e("tr",[e("td",{staticClass:"txt:bold",domProps:{textContent:t._s(s.$gettext("License owner (UID)"))}}),t._v(" "),e("td",[t._v(`
                            `+t._s(s.license.uid)+`
                        `)])]),t._v(" "),e("tr",[e("td",{staticClass:"txt:bold",domProps:{textContent:t._s(s.$gettext("Type"))}}),t._v(" "),e("td",[t._v(`
                            `+t._s(s.license.type)+`
                        `)])]),t._v(" "),e("tr",[e("td",{staticClass:"txt:bold",domProps:{textContent:t._s(s.$gettext("Valid until"))}}),t._v(" "),e("td",[t._v(`
                            `+t._s(s.date(new Date(s.license.expires),"datetime"))+`
                        `)])]),t._v(" "),e("tr",[e("td",{staticClass:"txt:bold",domProps:{textContent:t._s(s.$gettext("Accounts"))}}),t._v(" "),e("td",[t._v(`
                            `+t._s(s.license.usage.users)+` /
                            `),e("span",{domProps:{textContent:t._s(s.license.limits.maxUsers||s.$gettext("Unlimited"))}})])]),t._v(" "),e("tr",[e("td",{staticClass:"txt:bold",domProps:{textContent:t._s(s.$gettext("Resellers"))}}),t._v(" "),e("td",[t._v(`
                            `+t._s(s.license.usage.adminsOrResellers)+` /
                            `),e("span",{domProps:{textContent:t._s(s.license.limits.maxAdminsOrResellers||s.$gettext("Unlimited"))}})])]),t._v(" "),e("tr",[e("td",{staticClass:"txt:bold",domProps:{textContent:t._s(s.$gettext("Domains"))}}),t._v(" "),e("td",[t._v(`
                            `+t._s(s.license.usage.domains)+` /
                            `),e("span",{domProps:{textContent:t._s(s.license.limits.maxDomains||s.$gettext("Unlimited"))}})])]),t._v(" "),e("tr",[e("td",{staticClass:"txt:bold",domProps:{textContent:t._s(s.$gettext("VPS Only"))}}),t._v(" "),e("td",[e("ui-badge",{attrs:{theme:s.license.limits.onlyVPS?"safe":"primary",size:"big"}},[e("span",{domProps:{textContent:t._s(s.license.limits.onlyVPS?s.$gettext("Yes"):s.$gettext("No"))}})])],1)]),t._v(" "),e("tr",[e("td",{staticClass:"txt:bold",domProps:{textContent:t._s(s.$gettext("Pro Pack"))}}),t._v(" "),e("td",[e("ui-badge",{attrs:{theme:s.license.limits.proPack?"safe":"primary",size:"big"}},[e("span",{domProps:{textContent:t._s(s.license.limits.proPack?s.$gettext("Yes"):s.$gettext("No"))}})])],1)]),t._v(" "),e("tr",[e("td",{staticClass:"txt:bold",domProps:{textContent:t._s(s.$gettext("Codebase"))}}),t._v(" "),e("td",[e("ui-badge",{attrs:{theme:s.license.limits.legacy?"danger":"safe",size:"big"}},[e("span",{domProps:{textContent:t._s(s.license.limits.legacy?s.$gettext("DirectAdmin legacy"):s.$gettext("DirectAdmin"))}})])],1)])])]),t._v(" "),t._v(" "),e(s.LicenseProofDialog,{attrs:{license:s.licenseVerificationData,proof:s.item.proof,url:s.item.checkUrl}})],1)]},proxy:!0}])})},l=[],c=n("../node_modules/vue/dist/vue.common.prod.js"),x=n("./js/composables/useDataStore.ts"),P=n("./js/openapi/license.ts"),u=n("./js/composables/index.ts");const{$gettext:f,$gettextInterpolate:M}=(0,u.st)(),U=(0,u.d$)(),{data:Z,request:T}=(0,x.a)(P.l),A=async()=>{const v=await T();return v.status==="error"&&U.error({title:f("Error"),content:M(f("Failed to load %{subject}!"),{subject:f("license")})}),v};var j=n("./js/composables/filters.ts"),b=n("./js/gettext.js");const I={400:(0,b.$gettext)("Proof is invalid"),404:(0,b.$gettext)("License or License session doesn't exist"),409:(0,b.$gettext)("Proof is expired"),500:(0,b.$gettext)("Unexpected database error"),default:(0,b.$gettext)("Unexpected error"),json:(0,b.$gettext)("Failed to reach returned JSON")},S=async v=>{const t=await fetch(`https://licensing.directadmin.com/verify?proof=${v}`);if(t.ok){const e=t.headers.get("content-type");return e&&e.includes("application/json")?t.json():{error:I.json}}else return{error:I[t.status]||I.default}};var a=async v=>await S(v),_=function(){var t=this,e=t._self._c;return e("ui-dialog",{attrs:{id:"LICENSE_PROOF_DIALOG",title:t.$gettext("License Proof"),"no-auto-close":"",cancel:!1,theme:"primary",size:"normal"},scopedSlots:t._u([{key:"content",fn:function(){return[e("table",{staticClass:"table-elem"},[e("tbody",[e("tr",[e("td",{staticClass:"txt:bold",domProps:{textContent:t._s(t.$gettext("Name"))}}),t._v(" "),e("td",[t._v(`
                        `+t._s(t.license.name)+`
                    `)])]),t._v(" "),e("tr",[e("td",{staticClass:"txt:bold",domProps:{textContent:t._s(t.$gettext("License ID (LID)"))}}),t._v(" "),e("td",[t._v(`
                        `+t._s(t.license.lid)+`
                        `),t.license.trial?e("ui-badge",{attrs:{theme:"danger",size:"small",label:"Trial"}}):t._e()],1)]),t._v(" "),e("tr",[e("td",{staticClass:"txt:bold",domProps:{textContent:t._s(t.$gettext("License owner (UID)"))}}),t._v(" "),e("td",[t._v(`
                        `+t._s(t.license.uid)+`
                    `)])]),t._v(" "),e("tr",[e("td",{staticClass:"txt:bold",domProps:{textContent:t._s(t.$gettext("Type"))}}),t._v(" "),e("td",[t._v(`
                        `+t._s(t.license.type)+`
                    `)])]),t._v(" "),t.license.expiry?e("tr",[e("td",{staticClass:"txt:bold",domProps:{textContent:t._s(t.$gettext("Valid until"))}}),t._v(" "),e("td",[t._v(`
                        `+t._s(t.date(new Date(t.license.expiry),"datetime"))+`
                    `)])]):t._e(),t._v(" "),t.license.limits?e("tr",[e("td",{staticClass:"txt:bold",domProps:{textContent:t._s(t.$gettext("Accounts"))}}),t._v(" "),e("td",[t._v(`
                        `+t._s(t.license.limits.maxUsers||t.$gettext("Unlimited"))+`
                    `)])]):t._e(),t._v(" "),t.license.limits?e("tr",[e("td",{staticClass:"txt:bold",domProps:{textContent:t._s(t.$gettext("Resellers"))}}),t._v(" "),e("td",[t._v(`
                        `+t._s(t.license.limits.maxAdminsOrResellers||t.$gettext("Unlimited"))+`
                    `)])]):t._e(),t._v(" "),t.license.limits?e("tr",[e("td",{staticClass:"txt:bold",domProps:{textContent:t._s(t.$gettext("Domains"))}}),t._v(" "),e("td",[t._v(`
                        `+t._s(t.license.limits.maxDomains||t.$gettext("Unlimited"))+`
                    `)])]):t._e(),t._v(" "),t.license.limits?e("tr",[e("td",{staticClass:"txt:bold",domProps:{textContent:t._s(t.$gettext("VPS Only"))}}),t._v(" "),e("td",[e("ui-badge",{attrs:{theme:t.license.limits.onlyVPS?"safe":"primary",size:"big"}},[t._v(`
                            `+t._s(t.license.limits.onlyVPS?t.$gettext("Yes"):t.$gettext("No"))+`
                        `)])],1)]):t._e(),t._v(" "),e("tr",[e("td",{staticClass:"txt:bold",domProps:{textContent:t._s(t.$gettext("Pro Pack"))}}),t._v(" "),e("td",[e("ui-badge",{attrs:{theme:t.license.propack?"safe":"primary",size:"big"}},[t._v(`
                            `+t._s(t.license.propack?t.$gettext("Yes"):t.$gettext("No"))+`
                        `)])],1)]),t._v(" "),t.license.limits?e("tr",[e("td",{staticClass:"txt:bold",domProps:{textContent:t._s(t.$gettext("Legacy"))}}),t._v(" "),e("td",[e("ui-badge",{attrs:{theme:t.license.limits.legacy?"danger":"safe",size:"big"}},[t._v(`
                            `+t._s(t.license.limits.legacy?t.$gettext("Yes"):t.$gettext("No"))+`
                        `)])],1)]):t._e(),t._v(" "),e("tr",[e("td",{staticClass:"txt:bold",domProps:{textContent:t._s(t.$gettext("Commit"))}}),t._v(" "),e("td",[t._v(`
                        `+t._s(t.license.commit)+`
                    `)])]),t._v(" "),e("tr",[e("td",{staticClass:"txt:bold",domProps:{textContent:t._s(t.$gettext("IP"))}}),t._v(" "),e("td",[t._v(`
                        `+t._s(t.license.ip)+`
                    `)])]),t._v(" "),e("tr",[e("td",{staticClass:"txt:bold",domProps:{textContent:t._s(t.$gettext("Machine ID"))}}),t._v(" "),e("td",[t._v(`
                        `+t._s(t.license.machineUUID)+`
                    `)])]),t._v(" "),e("tr",[e("td",{staticClass:"txt:bold",domProps:{textContent:t._s(t.$gettext("OS kernel info"))}}),t._v(" "),e("td",[t._v(`
                        `+t._s(t.license.osInfo)+`
                    `)])]),t._v(" "),e("tr",[e("td",{staticClass:"txt:bold",domProps:{textContent:t._s(t.$gettext("Version"))}}),t._v(" "),e("td",[t._v(`
                        `+t._s(t.license.version)+`
                    `)])]),t._v(" "),e("tr",{staticStyle:{"word-break":"break-word"}},[e("td",{staticClass:"txt:bold"},[e("span",{domProps:{textContent:t._s(t.$gettext("Proof value"))}}),t._v(" "),e("ui-link",{attrs:{href:t.url,target:"_blank",title:t.$gettext("Check url")}},[e("ui-icon",{attrs:{id:"refreshed-link",theme:"primary",size:16}})],1)],1),t._v(" "),e("td",[t._v(`
                        `+t._s(t.proof)+`
                    `)])])])])]},proxy:!0}])})},D=[],y={props:{license:{type:Object,required:!0},proof:{type:String,required:!0},url:{type:String,required:!0}},methods:{date:j.hT}},L=y,B=n("../node_modules/vue-loader/lib/runtime/componentNormalizer.js"),i=(0,B.Z)(L,_,D,!1,null,null,null),r=i.exports;const o=(0,c.defineComponent)({async beforeRouteEnter(v,t,e){if((await A()).error)return e(!1);e()}});var m=(0,c.defineComponent)({...o,__name:"index",emits:[],setup(v){const{$gettext:t}=(0,u.st)(),e=(0,u.Lu)({LICENSE_SESSION_NOT_CONNECTED:t("License session not being connected")}),s=(0,u.Rh)("LICENSE_PROOF_DIALOG"),E=(0,c.ref)({proof:"",checkUrl:""}),z=(0,c.ref)({}),p=async()=>{const{data:R,error:W}=await(0,P.o)();if(W){e(W);return}Object.assign(E.value,R),O()},O=async()=>{const R=await a(E.value.proof);if(R.error){(0,u.d$)().error({title:t("License checks cannot be performed"),content:R.error});return}z.value=R,s.open()};return{__sfc:!0,$gettext:t,notifyError:e,licenseProofDialog:s,item:E,licenseVerificationData:z,proofLicense:p,verify:O,license:Z,date:j.hT,LicenseProofDialog:r}}}),g=m,$=(0,B.Z)(g,C,l,!1,null,null,null),d=$.exports}}]);
