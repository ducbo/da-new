"use strict";(self.webpackChunk=self.webpackChunk||[]).push([[3078],{"../node_modules/date-fns/esm/formatDistance/index.js":function(w,y,o){o.d(y,{Z:function(){return e}});var R=o("../node_modules/date-fns/esm/_lib/defaultOptions/index.js"),i=o("../node_modules/date-fns/esm/toDate/index.js"),f=o("../node_modules/date-fns/esm/_lib/requiredArgs/index.js");function c(t,n){(0,f.Z)(2,arguments);var s=(0,i.Z)(t),v=(0,i.Z)(n),_=s.getTime()-v.getTime();return _<0?-1:_>0?1:_}function x(t,n){(0,f.Z)(2,arguments);var s=(0,i.Z)(t),v=(0,i.Z)(n),_=s.getFullYear()-v.getFullYear(),E=s.getMonth()-v.getMonth();return _*12+E}function m(t){(0,f.Z)(1,arguments);var n=(0,i.Z)(t);return n.setHours(23,59,59,999),n}function D(t){(0,f.Z)(1,arguments);var n=(0,i.Z)(t),s=n.getMonth();return n.setFullYear(n.getFullYear(),s+1,0),n.setHours(23,59,59,999),n}function M(t){(0,f.Z)(1,arguments);var n=(0,i.Z)(t);return m(n).getTime()===D(n).getTime()}function I(t,n){(0,f.Z)(2,arguments);var s=(0,i.Z)(t),v=(0,i.Z)(n),_=c(s,v),E=Math.abs(x(s,v)),u;if(E<1)u=0;else{s.getMonth()===1&&s.getDate()>27&&s.setDate(30),s.setMonth(s.getMonth()-_*E);var k=c(s,v)===-_;M((0,i.Z)(t))&&E===1&&c(t,v)===1&&(k=!1),u=_*(E-Number(k))}return u===0?0:u}function b(t,n){return(0,f.Z)(2,arguments),(0,i.Z)(t).getTime()-(0,i.Z)(n).getTime()}var S={ceil:Math.ceil,round:Math.round,floor:Math.floor,trunc:function(n){return n<0?Math.ceil(n):Math.floor(n)}},j="trunc";function T(t){return t?S[t]:S[j]}function $(t,n,s){(0,f.Z)(2,arguments);var v=b(t,n)/1e3;return T(s==null?void 0:s.roundingMethod)(v)}var N=o("../node_modules/date-fns/esm/_lib/defaultLocale/index.js");function Z(t,n){if(t==null)throw new TypeError("assign requires that input parameter not be null or undefined");for(var s in n)Object.prototype.hasOwnProperty.call(n,s)&&(t[s]=n[s]);return t}function U(t){return Z({},t)}var r=o("../node_modules/date-fns/esm/_lib/getTimezoneOffsetInMilliseconds/index.js"),l=1440,h=2520,g=43200,a=86400;function e(t,n,s){var v,_;(0,f.Z)(2,arguments);var E=(0,R.j)(),u=(v=(_=s==null?void 0:s.locale)!==null&&_!==void 0?_:E.locale)!==null&&v!==void 0?v:N.Z;if(!u.formatDistance)throw new RangeError("locale must contain formatDistance property");var k=c(t,n);if(isNaN(k))throw new RangeError("Invalid time value");var d=Z(U(s),{addSuffix:Boolean(s==null?void 0:s.addSuffix),comparison:k}),A,C;k>0?(A=(0,i.Z)(n),C=(0,i.Z)(t)):(A=(0,i.Z)(t),C=(0,i.Z)(n));var O=$(C,A),F=((0,r.Z)(C)-(0,r.Z)(A))/1e3,p=Math.round((O-F)/60),P;if(p<2)return s!=null&&s.includeSeconds?O<5?u.formatDistance("lessThanXSeconds",5,d):O<10?u.formatDistance("lessThanXSeconds",10,d):O<20?u.formatDistance("lessThanXSeconds",20,d):O<40?u.formatDistance("halfAMinute",0,d):O<60?u.formatDistance("lessThanXMinutes",1,d):u.formatDistance("xMinutes",1,d):p===0?u.formatDistance("lessThanXMinutes",1,d):u.formatDistance("xMinutes",p,d);if(p<45)return u.formatDistance("xMinutes",p,d);if(p<90)return u.formatDistance("aboutXHours",1,d);if(p<l){var W=Math.round(p/60);return u.formatDistance("aboutXHours",W,d)}else{if(p<h)return u.formatDistance("xDays",1,d);if(p<g){var X=Math.round(p/l);return u.formatDistance("xDays",X,d)}else if(p<a)return P=Math.round(p/g),u.formatDistance("aboutXMonths",P,d)}if(P=I(C,A),P<12){var z=Math.round(p/g);return u.formatDistance("xMonths",z,d)}else{var L=P%12,B=Math.floor(P/12);return L<3?u.formatDistance("aboutXYears",B,d):L<9?u.formatDistance("overXYears",B,d):u.formatDistance("almostXYears",B+1,d)}}},"./js/composables/dateFilter.ts":function(w,y,o){o.d(y,{W:function(){return x},f:function(){return f.f}});var R=o("../node_modules/ramda/es/index.js"),i=o("../node_modules/date-fns/esm/format/index.js"),f=o("./js/modules/date-formats.ts"),c=o("./js/modules/customizations/date-formats/default.ts");const x=R.WAo((m,D)=>{if(D)try{return(0,i.Z)(D,f.f.value[m])}catch(M){return console.warn(`Given ${m} format is incorrect:
${M.message}`),(0,i.Z)(D,c.d[m])}return""})},"./js/composables/filters.ts":function(w,y,o){o.d(y,{Q0:function(){return $},aS:function(){return Z},d5:function(){return N},eB:function(){return S},hT:function(){return I},kC:function(){return M},n9:function(){return T},zM:function(){return b}});var R=o("../node_modules/date-fns/esm/formatDistance/index.js"),i=o("../node_modules/punycode/punycode.es6.js"),f=o("./js/composables/dateFilter.ts"),c=o("./js/composables/gettext.ts");const{$gettext:x,$ngettext:m,$gettextInterpolate:D}=(0,c.Z)(),M=r=>{var l;return r?((l=r.at(0))===null||l===void 0?void 0:l.toUpperCase())+r.slice(1):""},I=(r,l="datetime")=>(0,f.W)(l,r),b=r=>(0,R.Z)(r,new Date),S=(r,l=1024)=>{const h=Number(r);if(!h)return"0 B";const g=["B","KB","MB","GB","TB","PB","EB","ZB","YB"],a=Math.floor(Math.log(h)/Math.log(l));return`${parseFloat((h/l**a).toFixed(2))} ${g[a]}`},j=r=>{try{return(0,i.xX)(r)}catch(l){return r}},T=r=>(0,i.xX)(r),$=r=>{if(!r||!r.includes("@"))return r;const[l,h]=r.split("@");return[l,j(h)].join("@")},N=r=>{if(r<60)return x("less than a minute");const l=Math.floor(r/60)%60,h=Math.floor(r/3600)%24,g=Math.floor(r/(3600*24)),a=[g?m("%{days} day","%{days} days",g):null,h?m("%{hours} hour","%{hours} hours",h):null,l?m("%{minutes} minute","%{minutes} minutes",l):null].filter(Boolean).join(", ");return D(a,{days:g,hours:h,minutes:l})},Z=(r,l)=>r.length<=l?r:`${r.substring(0,l)}...`,U=()=>({capitalize:M,date:I,distanceFromNow:b,humanReadableSize:S,p6eUnicode:T,p6eUnicodeEmail:$,formatUptime:N,truncateString:Z})},"./js/pages/reseller/nameservers.vue":function(w,y,o){o.r(y),o.d(y,{default:function(){return g}});var R=function(){var e=this,t=e._self._c;return t("app-page",{attrs:{actions:[{label:e.$gettext("Create Name Servers"),theme:"primary",icon:"#plus-fill",handler:e.$dialog("CREATE_NAMESERVERS_DIALOG").open}]},scopedSlots:e._u([{key:"default",fn:function(){return[t("app-page-section",[t("ui-r-table",{attrs:{columns:[{id:"ip",label:e.$gettext("IP"),editable:!1},{id:"status",label:e.$gettext("Status")},{id:"value",label:e.$gettext("User(s)")},{id:"ns",label:e.$gettext("Name Server"),editable:!1}],rows:e.$api.servers.ips,"checked-rows":e.checkedRows,"vertical-layout":e.clientStore.isPhone,"disable-pagination":"","equal-width-layout":""},on:{"update:checkedRows":function(n){e.checkedRows=n}},scopedSlots:e._u([{key:"table:actions",fn:function(){return[t("ui-table-action",{attrs:{disabled:!e.actions.delete},on:{click:function(n){e.$dialog("DELETE_ITEMS_DIALOG").open()}}},[t("span",{domProps:{textContent:e._s(e.$gettext("Delete"))}})])]},proxy:!0},{key:"col:ns",fn:function({ns:n}){return[e._v(`
                    `+e._s(e.p6eUnicode(n))+`
                `)]}}])})],1),e._v(" "),t("app-page-section",{scopedSlots:e._u([{key:"section:title",fn:function(){return[t("span",{domProps:{textContent:e._s(e.$gettext("Set the Name servers that will be assigned to new users"))}})]},proxy:!0},{key:"default",fn:function(){return[t("ui-form-element",{attrs:{group:"setNameservers",validators:{required:!0,domain:!0}},scopedSlots:e._u([{key:"title",fn:function(){return[t("span",{domProps:{textContent:e._s(e.$gettext("Name Server 1"))}})]},proxy:!0},{key:"content",fn:function(){return[t("input-text",{model:{value:e.ns1,callback:function(n){e.ns1=n},expression:"ns1"}})]},proxy:!0}])}),e._v(" "),t("ui-form-element",{attrs:{group:"setNameservers",validators:{required:!0,domain:!0},underline:!1},scopedSlots:e._u([{key:"title",fn:function(){return[t("span",{domProps:{textContent:e._s(e.$gettext("Name Server 2"))}})]},proxy:!0},{key:"content",fn:function(){return[t("input-text",{model:{value:e.ns2,callback:function(n){e.ns2=n},expression:"ns2"}})]},proxy:!0}])})]},proxy:!0},{key:"footer:buttons",fn:function(){return[t("ui-button",{attrs:{theme:"safe","validate-group":"setNameservers"},on:{click:e.updateDefaults}},[t("span",{domProps:{textContent:e._s(e.$gettext("Save"))}})])]},proxy:!0}])}),e._v(" "),t("create-nameservers-dialog",{attrs:{"force-virtual":!e.actions.create},on:{create:function(n){e.checkedRows=[]}}}),e._v(" "),t("ui-dialog-delete-items",{attrs:{subject:e.$gettext("nameserver")},on:{"click:confirm":e.deleteNameservers}})]},proxy:!0}])})},i=[],f=o("./js/stores/index.ts"),c=o("./js/api/command/index.js");const x="/CMD_NAME_SERVER",m=c.Z.get({id:"NAMESERVERS",url:x,after:a=>a.flow(a.project({ips:"data",domains:"domains",defaultDomain:"domains","nameservers.ns1":"ns1","nameservers.ns2":"ns2"}),a.mapProps({ips:a.flow(a.mapValues((e,t)=>({...e,ip:t})),a.toArray,a.mapArray(a.getProps(["ip","status","value","ns"]))),domains:a.flow(a.mapValues(a.getProp("value")),a.toArray),defaultDomain:a.flow(a.find(a.getProp("selected")),a.getProp("value"))}))}),D=c.Z.select({url:x,params:{delete:!0}}),M=c.Z.select({url:x,params:{create:!0},schema:{ns1:c.Z.REQUIRED_STRING,ns2:c.Z.REQUIRED_STRING,domain:c.Z.REQUIRED_STRING,virtual:c.Z.REQUIRED_BOOL}}),I=c.Z.post({url:x,params:{action:"modify"},schema:{ns1:c.Z.REQUIRED_STRING,ns2:c.Z.REQUIRED_STRING}});var b=function(){var e=this,t=e._self._c;return t("ui-dialog",{attrs:{id:"CREATE_NAMESERVERS_DIALOG",size:"normal",title:e.$gettext("Create Name Servers")},on:{"dialog:open":e.selectDefaultDomain,"dialog:close":e.resetData},scopedSlots:e._u([{key:"content",fn:function(){return[t("ui-form-element",{attrs:{vertical:""},scopedSlots:e._u([{key:"title",fn:function(){return[t("span",{domProps:{textContent:e._s(e.$gettext("Domain:"))}})]},proxy:!0},{key:"content",fn:function(){return[t("input-select",{attrs:{options:e.domains},scopedSlots:e._u([{key:"additions:right",fn:function(){return[t("input-checkbox-button",{attrs:{theme:"light",disabled:e.forceVirtual},model:{value:e.virtual,callback:function(n){e.virtual=n},expression:"virtual"}},[t("span",{domProps:{textContent:e._s(e.$gettext("Virtual"))}})])]},proxy:!0}]),model:{value:e.domain,callback:function(n){e.domain=n},expression:"domain"}})]},proxy:!0}])}),e._v(" "),t("ui-form-element",{attrs:{vertical:""},scopedSlots:e._u([{key:"title",fn:function(){return[t("span",{domProps:{textContent:e._s(e.$gettext("Name Server 1:"))}})]},proxy:!0},{key:"content",fn:function(){return[t("input-text",{attrs:{suffix:e.suffix},model:{value:e.ns1.name,callback:function(n){e.$set(e.ns1,"name",n)},expression:"ns1.name"}})]},proxy:!0}])}),e._v(" "),e.virtual?e._e():t("ui-form-element",{attrs:{vertical:""},scopedSlots:e._u([{key:"content",fn:function(){return[t("input-select",{attrs:{options:e.ips},model:{value:e.ns1.ip,callback:function(n){e.$set(e.ns1,"ip",n)},expression:"ns1.ip"}})]},proxy:!0}],null,!1,698142759)}),e._v(" "),t("ui-form-element",{attrs:{vertical:""},scopedSlots:e._u([{key:"title",fn:function(){return[t("span",{domProps:{textContent:e._s(e.$gettext("Name Server 2:"))}})]},proxy:!0},{key:"content",fn:function(){return[t("input-text",{attrs:{suffix:e.suffix},model:{value:e.ns2.name,callback:function(n){e.$set(e.ns2,"name",n)},expression:"ns2.name"}})]},proxy:!0}])}),e._v(" "),e.virtual?e._e():t("ui-form-element",{attrs:{vertical:""},scopedSlots:e._u([{key:"content",fn:function(){return[t("input-select",{attrs:{options:e.ips},model:{value:e.ns2.ip,callback:function(n){e.$set(e.ns2,"ip",n)},expression:"ns2.ip"}})]},proxy:!0}],null,!1,2464071428)})]},proxy:!0},{key:"buttons",fn:function(){return[t("ui-button",{attrs:{theme:"primary"},on:{click:e.create}},[t("span",{domProps:{textContent:e._s(e.$gettext("Create Name Servers"))}})])]},proxy:!0}])})},S=[],j={api:[{command:m,bind:"servers"}],props:{forceVirtual:{type:Boolean,required:!1,default:!1}},data(){return{domain:"",ns1:{name:"ns1",ip:""},ns2:{name:"ns2",ip:""},virtual:this.forceVirtual}},computed:{apiData(){return this.$api.servers},domains(){return this.apiData.domains},ips(){return this.apiData.ips.map(a=>a.ip)},select(){return[this.ns1.ip,this.ns2.ip]},suffix(){return this.domain?`.${this.domain}`:""},requestData(){return{domain:this.domain,select:this.select,ns1:this.ns1.name,ns2:this.ns2.name,virtual:this.virtual}}},methods:{selectDefaultDomain(){this.domain=this.domains[0]||""},async create(){await M(this.requestData),m(),this.$emit("create"),this.resetData()},resetData(){Object.assign(this.$data,this.$options.data.apply(this))}}},T=j,$=o("../node_modules/vue-loader/lib/runtime/componentNormalizer.js"),N=(0,$.Z)(T,b,S,!1,null,null,null),Z=N.exports,U=o("./js/composables/filters.ts"),r={preload:m,api:[{command:m,bind:"servers"}],components:{CreateNameserversDialog:Z},data:()=>({ns1:"",ns2:"",checkedRows:[]}),computed:{checkedIPs(){return this.checkedRows.map(a=>a.ip)},canDelete(){if(this.checkedRows.length!==2||this.checkedRows.some(e=>!e.ns))return!1;const a=this.$api.servers.domains.find(e=>this.checkedRows[0].ns.includes(e));return this.checkedRows[1].ns.includes(a)},actions(){return{create:this.$api.servers.ips.filter(e=>!e.ns).length>=2,delete:this.canDelete}},...(0,f.Kc)(["client"])},created(){this.ns1=this.$p6e.toU(this.$api.servers.nameservers.ns1),this.ns2=this.$p6e.toU(this.$api.servers.nameservers.ns2)},methods:{p6eUnicode:U.n9,reloadRows(){m(),this.checkedRows=[]},updateDefaults(){I({ns1:this.$p6e.toA(this.ns1),ns2:this.$p6e.toA(this.ns2)}).then(this.reloadRows)},async deleteNameservers(){D({select:this.checkedIPs}).then(this.reloadRows)}}},l=r,h=(0,$.Z)(l,R,i,!1,null,null,null),g=h.exports}}]);
