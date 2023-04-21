"use strict";(self.webpackChunk=self.webpackChunk||[]).push([[3130],{"../node_modules/date-fns/esm/formatDistance/index.js":function(U,S,i){i.d(S,{Z:function(){return K}});var C=i("../node_modules/date-fns/esm/_lib/defaultOptions/index.js"),d=i("../node_modules/date-fns/esm/toDate/index.js"),_=i("../node_modules/date-fns/esm/_lib/requiredArgs/index.js");function v(r,s){(0,_.Z)(2,arguments);var n=(0,d.Z)(r),m=(0,d.Z)(s),p=n.getTime()-m.getTime();return p<0?-1:p>0?1:p}function g(r,s){(0,_.Z)(2,arguments);var n=(0,d.Z)(r),m=(0,d.Z)(s),p=n.getFullYear()-m.getFullYear(),$=n.getMonth()-m.getMonth();return p*12+$}function D(r){(0,_.Z)(1,arguments);var s=(0,d.Z)(r);return s.setHours(23,59,59,999),s}function k(r){(0,_.Z)(1,arguments);var s=(0,d.Z)(r),n=s.getMonth();return s.setFullYear(s.getFullYear(),n+1,0),s.setHours(23,59,59,999),s}function M(r){(0,_.Z)(1,arguments);var s=(0,d.Z)(r);return D(s).getTime()===k(s).getTime()}function P(r,s){(0,_.Z)(2,arguments);var n=(0,d.Z)(r),m=(0,d.Z)(s),p=v(n,m),$=Math.abs(g(n,m)),u;if($<1)u=0;else{n.getMonth()===1&&n.getDate()>27&&n.setDate(30),n.setMonth(n.getMonth()-p*$);var E=v(n,m)===-p;M((0,d.Z)(r))&&$===1&&v(r,m)===1&&(E=!1),u=p*($-Number(E))}return u===0?0:u}function I(r,s){return(0,_.Z)(2,arguments),(0,d.Z)(r).getTime()-(0,d.Z)(s).getTime()}var h={ceil:Math.ceil,round:Math.round,floor:Math.floor,trunc:function(s){return s<0?Math.ceil(s):Math.floor(s)}},N="trunc";function j(r){return r?h[r]:h[N]}function A(r,s,n){(0,_.Z)(2,arguments);var m=I(r,s)/1e3;return j(n==null?void 0:n.roundingMethod)(m)}var z=i("../node_modules/date-fns/esm/_lib/defaultLocale/index.js");function R(r,s){if(r==null)throw new TypeError("assign requires that input parameter not be null or undefined");for(var n in s)Object.prototype.hasOwnProperty.call(s,n)&&(r[n]=s[n]);return r}function L(r){return R({},r)}var o=i("../node_modules/date-fns/esm/_lib/getTimezoneOffsetInMilliseconds/index.js"),l=1440,y=2520,x=43200,Z=86400;function K(r,s,n){var m,p;(0,_.Z)(2,arguments);var $=(0,C.j)(),u=(m=(p=n==null?void 0:n.locale)!==null&&p!==void 0?p:$.locale)!==null&&m!==void 0?m:z.Z;if(!u.formatDistance)throw new RangeError("locale must contain formatDistance property");var E=v(r,s);if(isNaN(E))throw new RangeError("Invalid time value");var c=R(L(n),{addSuffix:Boolean(n==null?void 0:n.addSuffix),comparison:E}),O,T;E>0?(O=(0,d.Z)(s),T=(0,d.Z)(r)):(O=(0,d.Z)(r),T=(0,d.Z)(s));var b=A(T,O),a=((0,o.Z)(T)-(0,o.Z)(O))/1e3,e=Math.round((b-a)/60),t;if(e<2)return n!=null&&n.includeSeconds?b<5?u.formatDistance("lessThanXSeconds",5,c):b<10?u.formatDistance("lessThanXSeconds",10,c):b<20?u.formatDistance("lessThanXSeconds",20,c):b<40?u.formatDistance("halfAMinute",0,c):b<60?u.formatDistance("lessThanXMinutes",1,c):u.formatDistance("xMinutes",1,c):e===0?u.formatDistance("lessThanXMinutes",1,c):u.formatDistance("xMinutes",e,c);if(e<45)return u.formatDistance("xMinutes",e,c);if(e<90)return u.formatDistance("aboutXHours",1,c);if(e<l){var f=Math.round(e/60);return u.formatDistance("aboutXHours",f,c)}else{if(e<y)return u.formatDistance("xDays",1,c);if(e<x){var W=Math.round(e/l);return u.formatDistance("xDays",W,c)}else if(e<Z)return t=Math.round(e/x),u.formatDistance("aboutXMonths",t,c)}if(t=P(T,O),t<12){var X=Math.round(e/x);return u.formatDistance("xMonths",X,c)}else{var F=t%12,B=Math.floor(t/12);return F<3?u.formatDistance("aboutXYears",B,c):F<9?u.formatDistance("overXYears",B,c):u.formatDistance("almostXYears",B+1,c)}}},"./js/composables/dateFilter.ts":function(U,S,i){i.d(S,{W:function(){return g},f:function(){return _.f}});var C=i("../node_modules/ramda/es/index.js"),d=i("../node_modules/date-fns/esm/format/index.js"),_=i("./js/modules/date-formats.ts"),v=i("./js/modules/customizations/date-formats/default.ts");const g=C.WAo((D,k)=>{if(k)try{return(0,d.Z)(k,_.f.value[D])}catch(M){return console.warn(`Given ${D} format is incorrect:
${M.message}`),(0,d.Z)(k,v.d[D])}return""})},"./js/composables/filters.ts":function(U,S,i){i.d(S,{Q0:function(){return A},aS:function(){return R},d5:function(){return z},eB:function(){return h},hT:function(){return P},kC:function(){return M},n9:function(){return j},zM:function(){return I}});var C=i("../node_modules/date-fns/esm/formatDistance/index.js"),d=i("../node_modules/punycode/punycode.es6.js"),_=i("./js/composables/dateFilter.ts"),v=i("./js/composables/gettext.ts");const{$gettext:g,$ngettext:D,$gettextInterpolate:k}=(0,v.Z)(),M=o=>{var l;return o?((l=o.at(0))===null||l===void 0?void 0:l.toUpperCase())+o.slice(1):""},P=(o,l="datetime")=>(0,_.W)(l,o),I=o=>(0,C.Z)(o,new Date),h=(o,l=1024)=>{const y=Number(o);if(!y)return"0 B";const x=["B","KB","MB","GB","TB","PB","EB","ZB","YB"],Z=Math.floor(Math.log(y)/Math.log(l));return`${parseFloat((y/l**Z).toFixed(2))} ${x[Z]}`},N=o=>{try{return(0,d.xX)(o)}catch(l){return o}},j=o=>(0,d.xX)(o),A=o=>{if(!o||!o.includes("@"))return o;const[l,y]=o.split("@");return[l,N(y)].join("@")},z=o=>{if(o<60)return g("less than a minute");const l=Math.floor(o/60)%60,y=Math.floor(o/3600)%24,x=Math.floor(o/(3600*24)),Z=[x?D("%{days} day","%{days} days",x):null,y?D("%{hours} hour","%{hours} hours",y):null,l?D("%{minutes} minute","%{minutes} minutes",l):null].filter(Boolean).join(", ");return k(Z,{days:x,hours:y,minutes:l})},R=(o,l)=>o.length<=l?o:`${o.substring(0,l)}...`,L=()=>({capitalize:M,date:P,distanceFromNow:I,humanReadableSize:h,p6eUnicode:j,p6eUnicodeEmail:A,formatUptime:z,truncateString:R})},"./js/pages/user/dns/security.vue":function(U,S,i){i.r(S),i.d(S,{default:function(){return b}});var C=function(){var e=this,t=e._self._c;return t("app-page",{attrs:{actions:[{label:e.$gettext("Re-sign your zone"),visible:e.$api.status.zone&&e.$api.status.zoneOutdated,handler:e.signZone,icon:"#console"},{label:e.$gettext("Sign your Zone"),visible:e.$api.status.keys&&!e.$api.status.zone,handler:e.signZone,icon:"#console"},{label:e.$gettext("Clear Zone"),visible:e.$api.status.zone||e.$api.status.keys,handler:()=>e.requestConfirmation(e.clearZone),icon:"#cancel",theme:"danger"},{label:e.$gettext("Generate Keys"),handler:()=>e.requestConfirmation(e.generateKeys),icon:"#plus-fill",theme:"safe"}]},scopedSlots:e._u([{key:"default",fn:function(){return[e.$api.status.zone?t("app-page-section",{scopedSlots:e._u([{key:"section:title",fn:function(){return[t("ui-grid",{attrs:{cross:"center"}},[t("span",{domProps:{textContent:e._s(e.$gettext("Zone Signing"))}}),e._v(" "),e.$api.status.zoneOutdated?t("ui-badge",{attrs:{theme:"danger"}},[t("span",{domProps:{textContent:e._s(e.$gettext("Zone keys are newer than the Zone Signing."))}})]):e._e()],1)]},proxy:!0}],null,!1,2483167081)},[e._v(" "),e._l(e.zoneRows,function(f){return t("ui-form-element",{key:f.label,attrs:{vertical:e.clientStore.isPhone},scopedSlots:e._u([{key:"title",fn:function(){return[t("span",[e._v(e._s(f.label))])]},proxy:!0},{key:"content",fn:function(){return[f.date?t("span",[e._v(`
                        `+e._s(e.date(f.value,"datetime"))+`
                    `)]):t("ui-code-area",{attrs:{"break-lines":"",content:f.value}})]},proxy:!0}],null,!0)})})],2):e._e(),e._v(" "),e.$api.status.keys?t("app-page-section",{scopedSlots:e._u([{key:"section:title",fn:function(){return[e._v(e._s(e.$gettext("Zone Keys")))]},proxy:!0}],null,!1,1695514807)},[e._v(" "),t("table",[t("tr",[t("th",{domProps:{textContent:e._s(e.$gettext("Key"))}}),e._v(" "),t("th",{domProps:{textContent:e._s(e.$gettext("ID"))}}),e._v(" "),t("th",{domProps:{textContent:e._s(e.$gettext("Created"))}}),e._v(" "),t("th",{domProps:{textContent:e._s(e.$gettext("Published"))}}),e._v(" "),t("th",{domProps:{textContent:e._s(e.$gettext("Activated"))}})]),e._v(" "),e._l(e.keysRows,function(f){return[t("tr",{key:`${f.id}-first`},[t("td",{staticClass:"txt:bold"},[e._v(`
                            `+e._s(f.id)+`
                        `)]),e._v(" "),t("td",[e._v(e._s(f.data.id))]),e._v(" "),t("td",[e._v(e._s(e.date(f.data.created,"datetime")))]),e._v(" "),t("td",[e._v(e._s(e.date(f.data.published,"datetime")))]),e._v(" "),t("td",[e._v(e._s(e.date(f.data.activated,"datetime")))])]),e._v(" "),t("tr",{key:`${f.id}-second`},[t("td",{attrs:{colspan:"5"}},[t("ui-code-area",{attrs:{"break-lines":"",content:f.data.key}})],1)])]})],2),e._v(" "),t("ui-tabs",{attrs:{tabs:[{id:"zone",label:e.$gettext("Zone-Signing Key")},{id:"key",label:e.$gettext("Key-Signing Key")}]},scopedSlots:e._u([{key:"tab:zone",fn:function(){return[t("zone-key",e._b({attrs:{value:e.$api.keys.zone.key}},"zone-key",e.$api.keys.zone,!1))]},proxy:!0},{key:"tab:key",fn:function(){return[t("zone-key",e._b({attrs:{value:e.$api.keys.key.key}},"zone-key",e.$api.keys.key,!1))]},proxy:!0}],null,!1,410648928)})],1):e._e(),e._v(" "),e.$api.status.keys?e._e():t("app-page-section",[t("span",{staticClass:"c:txt:danger",domProps:{textContent:e._s(e.$gettext("Keys not yet generated."))}})]),e._v(" "),t("confirm-dialog",{on:{confirm:e.doAction,cancel:e.cancelAction}})]},proxy:!0}])})},d=[],_=i("./js/stores/index.ts"),v=i("./js/api/command/index.js"),g=i("./js/modules/constants.js"),D=i("./js/composables/index.ts");const k=()=>{const a={[g.ft.ADMIN]:"/CMD_DNS_ADMIN",[g.ft.USER]:"/CMD_DNS_CONTROL",[g.ft.RESELLER]:"/CMD_DNS_RESELLER"},e=(0,D.oR)("user"),t=(0,D.yj)();return t.path?t.path.includes(`${g.ft.ADMIN}/`)?a[g.ft.ADMIN]:t.path.includes(`${g.ft.RESELLER}/`)?a[g.ft.RESELLER]:a[g.ft.USER]:a[e.mode]},M=v.Z.post({url:k,params:{action:"dnssec"},domain:!0}),P=M.extend({params:{generate_keys:!0}}),I=M.extend({params:{sign_zone:!0}}),h=a=>a?new Date(a.replace(/.*\((.*)\)/,"$1")):"",N=(a,e)=>({keys:!!a.ksk_id,zone:a.DNS_DS!=="no",zoneOutdated:a.signed_on&&a.ksk_created?e.convert.toAppDate(a.signed_on)<h(a.ksk_created):!1}),j=(a,e)=>e.flow(e.project({expiryDate:"expiry",signedDate:"signed_on",DLV:"DLV",DS:"DS"}),e.mapProps({expiryDate:e.convert.toAppDate,signedDate:e.convert.toAppDate,DLV:e.convert.toAppHtml,DS:e.convert.toAppHtml}))(a),A=(a,e)=>e.flow(e.project({"zone.published":"zsk_publish","zone.id":"zsk_id","zone.created":"zsk_created","zone.activated":"zsk_activate","zone.key":"zsk_DNSKEY","key.published":"ksk_publish","key.id":"ksk_id","key.created":"ksk_created","key.activated":"ksk_activate","key.key":"ksk_DNSKEY"}),e.mapProps({zone:e.mapProps({published:h,created:h,activated:h}),key:e.mapProps({published:h,created:h,activated:h})}))(a),z=v.Z.post({url:k,id:"DNSSEC",params:{action:"dnssec",value:"get_keys"},domain:!0,response:{keys:!1,zone:!1},notifySuccess:!1,after:a=>e=>({status:N(e,a),zone:j(e,a),keys:A(e,a)})}),R=v.Z.post({url:k,params:{action:"dnssec",remove_dnssec:!0},schema:{ptr:v.Z.OPTIONAL_STRING,domain:v.Z.REQUIRED_STRING},domain:!0});var L=function(){var e=this,t=e._self._c;return t("ui-dialog",{attrs:{id:"CONFIRM_DNSSEC_DIALOG",theme:"danger","no-close-btn":"",title:e.$gettext("DNSSEC")},scopedSlots:e._u([{key:"content",fn:function(){return[t("div",[e._v(`
            `+e._s(e.$gettext("This action could cause domain resolution problems and cannot be undone. Are you sure you want to proceed?"))+`
        `)])]},proxy:!0},{key:"buttons",fn:function(){return[t("ui-button",{attrs:{theme:"danger"},on:{click:function(f){return e.$emit("confirm")}}},[t("span",{domProps:{textContent:e._s(e.$gettext("Confirm"))}})]),e._v(" "),t("ui-button",{attrs:{theme:"neutral"},on:{click:function(f){return e.$emit("cancel")}}},[t("span",{domProps:{textContent:e._s(e.$gettext("Cancel"))}})])]},proxy:!0}])})},o=[],l={},y=l,x=i("../node_modules/vue-loader/lib/runtime/componentNormalizer.js"),Z=(0,x.Z)(y,L,o,!1,null,null,null),K=Z.exports,r=function(){var e=this,t=e._self._c;return t("div",{staticClass:"zone-key"},[t("ui-form-element",{scopedSlots:e._u([{key:"title",fn:function(){return[t("span",{domProps:{textContent:e._s(e.$gettext("ID"))}})]},proxy:!0},{key:"content",fn:function(){return[t("span",{domProps:{textContent:e._s(e.id)}})]},proxy:!0}])}),e._v(" "),t("ui-form-element",{scopedSlots:e._u([{key:"title",fn:function(){return[t("span",{domProps:{textContent:e._s(e.$gettext("Created"))}})]},proxy:!0},{key:"content",fn:function(){return[t("span",[e._v(e._s(e.date(e.created,"datetime")))])]},proxy:!0}])}),e._v(" "),t("ui-form-element",{scopedSlots:e._u([{key:"title",fn:function(){return[t("span",{domProps:{textContent:e._s(e.$gettext("Published"))}})]},proxy:!0},{key:"content",fn:function(){return[t("span",[e._v(e._s(e.date(e.published,"datetime")))])]},proxy:!0}])}),e._v(" "),t("ui-form-element",{scopedSlots:e._u([{key:"title",fn:function(){return[t("span",{domProps:{textContent:e._s(e.$gettext("Activated"))}})]},proxy:!0},{key:"content",fn:function(){return[t("span",[e._v(e._s(e.date(e.activated,"datetime")))])]},proxy:!0}])}),e._v(" "),t("ui-form-element",{attrs:{vertical:""},scopedSlots:e._u([{key:"content",fn:function(){return[t("ui-code-area",{attrs:{"break-lines":"",content:e.value}})]},proxy:!0}])})],1)},s=[],n=i("./js/composables/filters.ts"),m={props:{id:String,created:Date,published:Date,activated:Date,value:String},methods:{date:n.hT}},p=m,$=(0,x.Z)(p,r,s,!1,null,null,null),u=$.exports,E=i("./js/context/index.ts"),c={name:"DnsSecurityExtensions",preload:({dom:a,pointer:e})=>z({ptr:e||null,domain:a||E.T.session.domain}),components:{ZoneKey:u,ConfirmDialog:K},api:[{command:z,bind:{"response.keys":"keys","response.status":"status","response.zone":"zone",isDone:"dataLoaded"}}],props:{dom:{type:String,required:!1,default(){return this.$domain}}},data:()=>({action:null}),computed:{keysRows(){return this.$api.status.keys?{zone:{id:this.$gettext("Zone-Signing Key"),data:this.$api.keys.zone},key:{id:this.$gettext("Key-Signing Key"),data:this.$api.keys.key}}:{}},zoneRows(){return[{label:this.$gettext("Signed"),value:this.$api.zone.signedDate},{label:this.$gettext("Expiry"),value:this.$api.zone.expiryDate},{label:this.$gettext("DS Record"),value:this.$api.zone.DS},{label:this.$gettext("DLV Record"),value:this.$api.zone.DLV}].map(a=>({...a,date:a.value instanceof Date}))},ptr(){return this.$route.query.pointer||null},...(0,_.Kc)(["client"])},watch:{$domain:"updateData"},methods:{date:n.hT,updateData(){z({domain:this.dom||this.$domain,ptr:this.ptr})},generateKeys(){P({ptr:this.ptr,domain:this.dom||this.$domain}).then(this.updateData)},signZone(){I({ptr:this.ptr,domain:this.dom||this.$domain}).then(this.updateData)},clearZone(){R({ptr:this.ptr,domain:this.dom||this.$domain}).then(this.updateData)},requestConfirmation(a){this.action=a,this.$dialog("CONFIRM_DNSSEC_DIALOG").open()},async doAction(){typeof this.action=="function"&&this.action.call(this),this.action=null},cancelAction(){this.action=null}}},O=c,T=(0,x.Z)(O,C,d,!1,null,null,null),b=T.exports}}]);