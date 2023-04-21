(self.webpackChunk=self.webpackChunk||[]).push([[3507],{"./js/api/commands/admin/ip-manager/index.js":function(j,g,n){"use strict";n.r(g),n.d(g,{addIp:function(){return s},assignReseller:function(){return f},clearNamespace:function(){return t},deleteIps:function(){return i},getIps:function(){return p},removeReseller:function(){return l},setGlobal:function(){return _},validateIP:function(){return m}});var o=n("./js/api/command/index.js"),c=n("./js/gettext.js");const r="/CMD_IP_MANAGER",p=o.Z.get({url:r,id:"IP_MANAGER",response:{ips:[],info:{}},pagination:!0,after:e=>e.flow(e.moveProp({ips:"rows"}),e.deleteProp("num_ips"),e.processTableInfo("rows"),e.mapProps({rows:e.flow(e.toArray,e.mapArray(e.flow(e.moveProp("extra.creators","resellers"),e.mapProps({global:e.isEqual("yes")}))))}))}),f=o.Z.select({url:r,params:{assign:!0,json:!0},schema:{reseller:o.Z.REQUIRED_STRING}}),l=o.Z.select({url:r,params:{json:!0,remove:!0}}),t=o.Z.select({url:r,params:{json:!0,clear:!0}}),i=o.Z.select({url:`${r}?json=yes`,params:{json:!0,delete:!0}}),s=o.Z.post({url:r,params:{action:"add",json:!0,add_to_device_aware:!0},schema:{ip:o.Z.REQUIRED_STRING,netmask:o.Z.REQUIRED_STRING,add_to_device:o.Z.REQUIRED_BOOL}}),m=o.Z.get({url:r,id:"VALIDATE_IP",params:{comparison1:"equals"},schema:{value:o.Z.REQUIRED_STRING},before:({value:e})=>({value1:e,value:null}),after:()=>({ips:e})=>e.info.rows!=="0"?{valid:!1,message:(0,c.$gettext)("You already have this IP on your system.")}:{valid:!0}}),_=o.Z.select({url:r,params:{set_global:!0},schema:{global:o.Z.REQUIRED_BOOL}})},"./js/api/commands/reseller/ip-config.js":function(j,g,n){"use strict";n.d(g,{BN:function(){return p},gd:function(){return f},iE:function(){return r}});var o=n("./js/api/command/index.js");const c="/CMD_IP_CONFIG",r=o.Z.get({id:"IP_CONFIG",url:c,response:{},after:l=>l.flow(t=>({ips:t.data,hideUsersCount:t.hide_ip_user_numbers==="1",haveShared:t.have_shared==="1"||!0,select:t.ip_list||{}}),l.mapProp("ips",l.flow(l.mapValues((t,i)=>({ip:i,...t})),Object.values,l.mapArrayProps({linked_ips:t=>Object.values(l.mapValues(t,(i,s)=>({ip:s,apache:l.convert.toAppBoolean(i.apache),dns:l.convert.toAppBoolean(i.dns)}))),value:t=>l.convert.toAppNumber(t)||t}))),l.mapProp("select",l.toSelect))}),p=o.Z.select({url:c,params:{share:!0}}),f=o.Z.select({url:c,params:{free:"Free Selected"}})},"./js/vue-globals/mixins/local/inputValidation.js":function(j,g,n){"use strict";n.r(g),n.d(g,{$inputValidation:function(){return r}});var o=n("./js/vue-globals/helpers.js"),c=n("./js/stores/index.ts");const r={inject:{groupID:{default:null},inputID:{default:null},validators:{default:()=>({})}},props:{id:{type:String,required:!1,default(){return this.inputID}},group:{type:String,required:!1,default(){return this.groupID}},novalidate:{type:Boolean,required:!1,default(){return!Object.keys(this.validators).length}}},computed:{validationStore(){return(0,c.oR)(PiniaStores.VALIDATION)},valid(){return this.validationStore.isValid(this.group,this.id)},errorState(){return!this.novalidate&&this.isUpdated&&!this.valid},isUpdated(){var p;const f=(p=this.validationStore.groups[this.group])==null?void 0:p[this.id];return typeof f=="undefined"?!1:f.updated}},methods:{$validate(p){this.id&&!this.novalidate&&this.validationStore.validate(this.groupID,this.id,p,this.validators)}},created(){if(!this.novalidate){const{validate:p}=this.$options;p&&this.$watch(p,(0,o.Ds)(this.$validate,{trailing:!0,leading:!1,delay:200}),{immediate:!0})}},destroyed(){this.novalidate||this.validationStore.deleteInput(this.group,this.id)}}},"../node_modules/mini-css-extract-plugin/dist/loader.js??clonedRuleSet-13.use[1]!../node_modules/css-loader/dist/cjs.js??clonedRuleSet-13.use[2]!../node_modules/vue-loader/lib/loaders/stylePostLoader.js!../node_modules/postcss-loader/dist/cjs.js??clonedRuleSet-13.use[3]!../node_modules/sass-loader/dist/cjs.js??clonedRuleSet-13.use[4]!../node_modules/vue-loader/lib/index.js??vue-loader-options!../node_modules/unplugin/dist/webpack/loaders/transform.js?unpluginName=unplugin-vue-define-options!./js/components/local/input-ip.vue?vue&type=style&index=0&id=7be90e6c&prod&lang=scss&":function(){},"./js/components/local/utils/cidr.ts":function(j,g,n){"use strict";n.d(g,{T:function(){return o},x:function(){return c}});const o=r=>{if(!r)return"";const p=[];let f=Number(r);for(let l=0;l<4;l++){const t=Math.min(f,8);p.push(256-2**(8-t)),f-=t}return p.join(".")},c=r=>{if(!r)return"";const p=(t,i)=>t.split(i).length-1,f=t=>(t>>>0).toString(2);return p((t=>t.split(".").map(Number))(r).map(t=>f(t)).join(""),"1")}},"./js/components/local/utils/mask-definition.ts":function(j,g,n){"use strict";n.d(g,{Xm:function(){return l}});const o={addressDefinition:(t,{buffer:i},s)=>{const m=/^([0-9]|[1-9][0-9]|1[0-9][0-9]|2[0-4][0-9]|25[0-5])$/;return s-1>-1&&i[s-1]!=="."&&(i[s-2]&&i[s-2]!=="."?t=i[s-2]+i[s-1]+t:t=i[s-1]+t),m.test(t)},netmaskDefinition:(t,{buffer:i},s)=>{const m=/^3[0-2]$|^[0-2][0-9]$|^[0-9]$/;return i[s-1]!=="/"&&(t=i[s-1]+t),m.test(t)},netmaskDelimiterDefinition:t=>t==="/"},c={addressDefinition:(t,{buffer:i},s)=>{const m=/[A-Fa-f0-9]/;return s===1&&i[0]===":"?!1:m.test(t)},addressDelimiterDefinition:(t,{buffer:i},s)=>t===":"?i[s-1]===":"?!i.join("").includes("::"):!0:/[A-Fa-f0-9]/.test(t)?{insert:[{pos:s,c:":"},{pos:s+1,c:t}],caret:s+2}:!1,netmaskDefinition:(t,{buffer:i},s)=>{const m=i;m.length===s?m.push(t):m[s]=t;const _=Number(m.join("").split("/").at(-1));return _>=0&&_<=128},netmaskDelimiterDefinition:(t,{buffer:i},s)=>{if(!s)return!1;if(i[s-1]===":"&&t==="/")return s>=3&&i[s-2]===":";const[m]=i.join("").split("/"),_=m.split(":").map(e=>e.replace(/_/g,"")).join(":");return t==="/"&&_.includes(":")}},r={ipv4Definition:(t,{buffer:i},s)=>{const m=/25[0-5]|2[0-4][0-9]|[01][0-9][0-9]/;return i[s-1]!=="-"?(t=i[s-1]+t,i[s-2]!=="-"?t=i[s-2]+t:t=`0${t}`):t=`00${t}`,m.test(t)},ipv6Definition:t=>/[A-Fa-f0-9]/.test(t),delimiterDefinition:t=>t==="-"},p={ipv4:{i:{validator:o.addressDefinition,cardinality:1},n:{validator:o.netmaskDefinition,cardinality:1},"=":{validator:o.netmaskDelimiterDefinition,cardinality:1,placeholder:"/"}},ipv6:{I:{validator:c.addressDefinition,cardinality:1,casing:"lower"},N:{validator:c.netmaskDefinition},":":{validator:c.addressDelimiterDefinition,cardinality:1,placeholder:":"},"-":{validator:c.netmaskDelimiterDefinition,cardinality:1,placeholder:"/"}}},f={"!":{validator:r.delimiterDefinition,cardinality:1,placeholder:""},r:{validator:r.ipv4Definition,cardinality:1,placeholder:""},R:{validator:r.ipv6Definition,cardinality:1,placeholder:""}},l=(t,i=!1)=>{let s={};return t.forEach(m=>{s={...s,...p[m]}}),i&&(s={...s,...f}),s}},"./js/composables/dateFilter.ts":function(j,g,n){"use strict";n.d(g,{W:function(){return f},f:function(){return r.f}});var o=n("../node_modules/ramda/es/index.js"),c=n("../node_modules/date-fns/esm/format/index.js"),r=n("./js/modules/date-formats.ts"),p=n("./js/modules/customizations/date-formats/default.ts");const f=o.WAo((l,t)=>{if(t)try{return(0,c.Z)(t,r.f.value[l])}catch(i){return console.warn(`Given ${l} format is incorrect:
${i.message}`),(0,c.Z)(t,p.d[l])}return""})},"./js/composables/filters.ts":function(j,g,n){"use strict";n.d(g,{Q0:function(){return a},aS:function(){return y},d5:function(){return v},eB:function(){return _},hT:function(){return s},kC:function(){return i},n9:function(){return d},zM:function(){return m}});var o=n("../node_modules/date-fns/esm/formatDistance/index.js"),c=n("../node_modules/punycode/punycode.es6.js"),r=n("./js/composables/dateFilter.ts"),p=n("./js/composables/gettext.ts");const{$gettext:f,$ngettext:l,$gettextInterpolate:t}=(0,p.Z)(),i=u=>{var h;return u?((h=u.at(0))===null||h===void 0?void 0:h.toUpperCase())+u.slice(1):""},s=(u,h="datetime")=>(0,r.W)(h,u),m=u=>(0,o.Z)(u,new Date),_=(u,h=1024)=>{const x=Number(u);if(!x)return"0 B";const I=["B","KB","MB","GB","TB","PB","EB","ZB","YB"],D=Math.floor(Math.log(x)/Math.log(h));return`${parseFloat((x/h**D).toFixed(2))} ${I[D]}`},e=u=>{try{return(0,c.xX)(u)}catch(h){return u}},d=u=>(0,c.xX)(u),a=u=>{if(!u||!u.includes("@"))return u;const[h,x]=u.split("@");return[h,e(x)].join("@")},v=u=>{if(u<60)return f("less than a minute");const h=Math.floor(u/60)%60,x=Math.floor(u/3600)%24,I=Math.floor(u/(3600*24)),D=[I?l("%{days} day","%{days} days",I):null,x?l("%{hours} hour","%{hours} hours",x):null,h?l("%{minutes} minute","%{minutes} minutes",h):null].filter(Boolean).join(", ");return t(D,{days:I,hours:x,minutes:h})},y=(u,h)=>u.length<=h?u:`${u.substring(0,h)}...`,P=()=>({capitalize:i,date:s,distanceFromNow:m,humanReadableSize:_,p6eUnicode:d,p6eUnicodeEmail:a,formatUptime:v,truncateString:y})},"./js/components/local/input-ip.vue":function(j,g,n){"use strict";n.d(g,{Z:function(){return d}});var o=function(){var v=this,y=v._self._c;return y("ui-input-group",{staticClass:"width:100%",scopedSlots:v._u([{key:"additions:left",fn:function(){return[v.showVersionsSelect?y("input-select",{staticClass:"input-ip-version-select",attrs:{novalidate:"",options:{v4:"IPv4",v6:"IPv6"}},on:{change:function(P){return v.$emit("update:version",P)}},model:{value:v.dataVersion,callback:function(P){v.dataVersion=P},expression:"dataVersion"}}):v._e()]},proxy:!0},{key:"input",fn:function(){return[y("input",{ref:"input",staticClass:"input-ip-mask",attrs:{type:"text"},domProps:{value:v.innerValue},on:{input:v.emit,focus:v.moveCursor}})]},proxy:!0},{key:"additions:right",fn:function(){return[v._t("additions:right",null,null,{})]},proxy:!0}],null,!0)})},c=[],r=n("../node_modules/inputmask/dist/inputmask.js"),p=n.n(r),f=n("./js/vue-globals/mixins/local/inputValidation.js"),l=n("./js/components/local/utils/cidr.ts"),t=n("./js/components/local/utils/mask-definition.ts"),i={mixins:[f.$inputValidation],validate:"value",props:{value:{type:String,required:!0},netmask:{type:String,required:!1,default:""},version:{type:String,required:!1,default:"v4"},disableVersionSelect:{type:Boolean,required:!1,default:!1},allowRange:{type:Boolean,required:!1,default:!1}},data:()=>({focused:!1,dataVersion:"v4",innerCidr:null}),computed:{showVersionsSelect(){return!this.disableVersionSelect&&this.$_flags.server.ipv6},cidr(){return this.netmask?this.dataVersion==="v4"?(0,l.x)(this.netmask):this.netmask:this.netmask},innerValue(){return this.value&&this.innerCidr!==null?`${this.value}/${this.cidr}`:this.value},mask(){let a={v4:Array(4).fill("i[i[i]]").join("."),v6:`[I[I[I[I]]]]${Array(7).fill("[:[I[I[I[I]]]]]").join("")}`}[this.dataVersion];const v={v4:"[!r[r[r]]]",v6:"[!R[R[R[R]]]]"}[this.dataVersion],y={v4:"[=[n[n]]]",v6:"[-[N[N[N]]]]"}[this.dataVersion];return this.allowRange&&(a=`${a}${v}`),typeof this.netmask!="undefined"&&(a=`${a}${y}`),a}},watch:{version(a){this.dataVersion!==a&&(this.dataVersion=a)},dataVersion(a){a!==this.version&&(this.$emit("input",""),this.$emit("update:netmask","")),this.applyMask()},innerCidr(a,v){a!==null&&(v===null&&a===""&&(this.innerCidr=this.cidr),this.emitNetmask(a))}},mounted(){this.dataVersion=this.version,this.applyMask()},methods:{emit({target:{value:a}}){const[v,y]=a.split("/");this.innerCidr=a.includes("/")?y:null,this.$emit("input",v),a||this.emitNetmask("")},emitNetmask(a){return this.$emit("update:netmask",this.dataVersion==="v4"?(0,l.T)(a):a)},moveCursor(){this.value||this.$refs.input.setSelectionRange(0,0)},applyMask(){new(p())({mask:this.mask,keepStatic:!0,definitions:(0,t.Xm)(["ipv4","ipv6"],!0),onUnMask:v=>v,skipOptionalPartCharacter:"",placeholder:"_"}).mask(this.$refs.input)}}},s=i,m=n("../node_modules/vue-style-loader/index.js!../node_modules/mini-css-extract-plugin/dist/loader.js??clonedRuleSet-13.use[1]!../node_modules/css-loader/dist/cjs.js??clonedRuleSet-13.use[2]!../node_modules/vue-loader/lib/loaders/stylePostLoader.js!../node_modules/postcss-loader/dist/cjs.js??clonedRuleSet-13.use[3]!../node_modules/sass-loader/dist/cjs.js??clonedRuleSet-13.use[4]!../node_modules/vue-loader/lib/index.js??vue-loader-options!../node_modules/unplugin/dist/webpack/loaders/transform.js?unpluginName=unplugin-vue-define-options!./js/components/local/input-ip.vue?vue&type=style&index=0&id=7be90e6c&prod&lang=scss&"),_=n("../node_modules/vue-loader/lib/runtime/componentNormalizer.js"),e=(0,_.Z)(s,o,c,!1,null,null,null),d=e.exports},"./js/pages/admin/ip-manager/_dialogs/add-ip-dialog.vue":function(j,g,n){"use strict";n.d(g,{Z:function(){return m}});var o=function(){var e=this,d=e._self._c;return d("ui-dialog",{attrs:{id:"ADD_IP_DIALOG",theme:"primary",title:e.$gettext("Add IP Address")},scopedSlots:e._u([{key:"content",fn:function(){return[d("ui-form-element",{attrs:{group:"addIp",validators:{required:!0,validateIP:e.validateIP,validateRange:e.validateRange,api:e.validateUniqueness},vertical:""},scopedSlots:e._u([{key:"title",fn:function(){return[d("span",{domProps:{textContent:e._s(e.$gettext("IP Address"))}}),e._v(" "),d("ui-tooltip",[d("span",{staticClass:"disp:block",domProps:{textContent:e._s(e.$gettext("To add a range of IP addresses, enter a dash after the last digit. For example:"))}}),e._v(" "),d("span",{staticClass:"disp:block",domProps:{textContent:e._s(e.$gettext("111.111.111.111-114"))}}),e._v(" "),d("span",{staticClass:"disp:block",domProps:{textContent:e._s(e.$gettext("This will add IP addresses ranging from 111.111.111.111 to 111.111.111.114"))}})])]},proxy:!0},{key:"content",fn:function(){return[d("input-ip",{attrs:{version:e.version,netmask:e.netmask,"disable-version-select":!e.haveIPv6,"allow-range":""},on:{"update:version":function(a){e.version=a},"update:netmask":function(a){e.netmask=a}},model:{value:e.ip,callback:function(a){e.ip=a},expression:"ip"}})]},proxy:!0},{key:"error:validateIP",fn:function(){return[d("span",{domProps:{textContent:e._s(e.$gettext("Should be valid IP Address"))}})]},proxy:!0},{key:"error:validateRange",fn:function(){return[d("span",{domProps:{textContent:e._s(e.$gettext("Range end should be larger than start"))}})]},proxy:!0}])}),e._v(" "),d("ui-form-element",{attrs:{group:"addIp",validators:{required:!0,regex:e.regexps.ip},vertical:""},scopedSlots:e._u([{key:"title",fn:function(){return[d("span",{domProps:{textContent:e._s(e.$gettext("Netmask"))}})]},proxy:!0},{key:"content",fn:function(){return[e.version==="v4"?d("input-ip",{attrs:{"disable-version-select":""},model:{value:e.netmask,callback:function(a){e.netmask=a},expression:"netmask"}}):d("span",{domProps:{textContent:e._s(e.$gettext("For IPv6 IPs, use a /mask, eg: /64"))}})]},proxy:!0},{key:"error:regex",fn:function(){return[d("span",{domProps:{textContent:e._s(e.$gettext("Should be valid netmask"))}})]},proxy:!0}])}),e._v(" "),d("ui-form-element",{attrs:{vertical:""},scopedSlots:e._u([{key:"content",fn:function(){return[d("input-checkbox",{model:{value:e.addToDevice,callback:function(a){e.addToDevice=a},expression:"addToDevice"}},[d("span",{domProps:{textContent:e._s(e.$gettext("Add to device"))}})])]},proxy:!0}])})]},proxy:!0},{key:"buttons",fn:function(){return[d("ui-button",{attrs:{theme:"primary","validate-group":"addIp"},on:{click:e.submit}},[d("span",{domProps:{textContent:e._s(e.$gettext("Add IP"))}})])]},proxy:!0}])})},c=[],r=n("./js/components/local/input-ip.vue"),p=n("./js/api/commands/admin/ip-manager/index.js"),f=n("./js/modules/constants.js"),l={components:{InputIp:r.Z},data:()=>({ip:"",netmask:"255.255.255.0",version:"v4",addToDevice:!0}),computed:{haveIPv6(){return this.$_flags.server.ipv6}},created(){this.validateUniqueness.id="VALIDATE_IP",this.regexps=f.gk},methods:{async submit(){this.$emit("submit",{ip:this.ip,netmask:this.version==="v4"?this.netmask:`/${this.netmask}`,add_to_device:this.addToDevice}),Object.assign(this.$data,this.$options.data.apply(this))},validateIP(_){if(!_)return!0;const[e]=_.split("-");return this.regexps.ip.test(e)},validateRange(_){if(!_)return!0;const[e,d]=_.split("-"),a=e.split(this.version==="v4"?".":":").pop();if(!a||!d)return!0;const v=this.version==="v4"?10:16;return parseInt(d,v)>parseInt(a,v)},validateUniqueness({value:_}){return this.validateIP(_)?(0,p.validateIP)({value:_}):{valid:!0}}}},t=l,i=n("../node_modules/vue-loader/lib/runtime/componentNormalizer.js"),s=(0,i.Z)(t,o,c,!1,null,null,null),m=s.exports},"../node_modules/vue-style-loader/index.js!../node_modules/mini-css-extract-plugin/dist/loader.js??clonedRuleSet-13.use[1]!../node_modules/css-loader/dist/cjs.js??clonedRuleSet-13.use[2]!../node_modules/vue-loader/lib/loaders/stylePostLoader.js!../node_modules/postcss-loader/dist/cjs.js??clonedRuleSet-13.use[3]!../node_modules/sass-loader/dist/cjs.js??clonedRuleSet-13.use[4]!../node_modules/vue-loader/lib/index.js??vue-loader-options!../node_modules/unplugin/dist/webpack/loaders/transform.js?unpluginName=unplugin-vue-define-options!./js/components/local/input-ip.vue?vue&type=style&index=0&id=7be90e6c&prod&lang=scss&":function(j,g,n){var o=n("../node_modules/mini-css-extract-plugin/dist/loader.js??clonedRuleSet-13.use[1]!../node_modules/css-loader/dist/cjs.js??clonedRuleSet-13.use[2]!../node_modules/vue-loader/lib/loaders/stylePostLoader.js!../node_modules/postcss-loader/dist/cjs.js??clonedRuleSet-13.use[3]!../node_modules/sass-loader/dist/cjs.js??clonedRuleSet-13.use[4]!../node_modules/vue-loader/lib/index.js??vue-loader-options!../node_modules/unplugin/dist/webpack/loaders/transform.js?unpluginName=unplugin-vue-define-options!./js/components/local/input-ip.vue?vue&type=style&index=0&id=7be90e6c&prod&lang=scss&");o.__esModule&&(o=o.default),typeof o=="string"&&(o=[[j.id,o,""]]),o.locals&&(j.exports=o.locals);var c=n("../node_modules/vue-style-loader/lib/addStylesClient.js").Z,r=c("61c82612",o,!0,{})}}]);