"use strict";(self.webpackChunk=self.webpackChunk||[]).push([[5411],{"../node_modules/date-fns/esm/formatDistance/index.js":function(j,b,s){s.d(b,{Z:function(){return F}});var c=s("../node_modules/date-fns/esm/_lib/defaultOptions/index.js"),i=s("../node_modules/date-fns/esm/toDate/index.js"),d=s("../node_modules/date-fns/esm/_lib/requiredArgs/index.js");function m(r,a){(0,d.Z)(2,arguments);var o=(0,i.Z)(r),h=(0,i.Z)(a),_=o.getTime()-h.getTime();return _<0?-1:_>0?1:_}function D(r,a){(0,d.Z)(2,arguments);var o=(0,i.Z)(r),h=(0,i.Z)(a),_=o.getFullYear()-h.getFullYear(),P=o.getMonth()-h.getMonth();return _*12+P}function p(r){(0,d.Z)(1,arguments);var a=(0,i.Z)(r);return a.setHours(23,59,59,999),a}function x(r){(0,d.Z)(1,arguments);var a=(0,i.Z)(r),o=a.getMonth();return a.setFullYear(a.getFullYear(),o+1,0),a.setHours(23,59,59,999),a}function n(r){(0,d.Z)(1,arguments);var a=(0,i.Z)(r);return p(a).getTime()===x(a).getTime()}function M(r,a){(0,d.Z)(2,arguments);var o=(0,i.Z)(r),h=(0,i.Z)(a),_=m(o,h),P=Math.abs(D(o,h)),u;if(P<1)u=0;else{o.getMonth()===1&&o.getDate()>27&&o.setDate(30),o.setMonth(o.getMonth()-_*P);var O=m(o,h)===-_;n((0,i.Z)(r))&&P===1&&m(r,h)===1&&(O=!1),u=_*(P-Number(O))}return u===0?0:u}function w(r,a){return(0,d.Z)(2,arguments),(0,i.Z)(r).getTime()-(0,i.Z)(a).getTime()}var S={ceil:Math.ceil,round:Math.round,floor:Math.floor,trunc:function(a){return a<0?Math.ceil(a):Math.floor(a)}},T="trunc";function A(r){return r?S[r]:S[T]}function $(r,a,o){(0,d.Z)(2,arguments);var h=w(r,a)/1e3;return A(o==null?void 0:o.roundingMethod)(h)}var y=s("../node_modules/date-fns/esm/_lib/defaultLocale/index.js");function E(r,a){if(r==null)throw new TypeError("assign requires that input parameter not be null or undefined");for(var o in a)Object.prototype.hasOwnProperty.call(a,o)&&(r[o]=a[o]);return r}function I(r){return E({},r)}var e=s("../node_modules/date-fns/esm/_lib/getTimezoneOffsetInMilliseconds/index.js"),t=1440,l=2520,v=43200,Z=86400;function F(r,a,o){var h,_;(0,d.Z)(2,arguments);var P=(0,c.j)(),u=(h=(_=o==null?void 0:o.locale)!==null&&_!==void 0?_:P.locale)!==null&&h!==void 0?h:y.Z;if(!u.formatDistance)throw new RangeError("locale must contain formatDistance property");var O=m(r,a);if(isNaN(O))throw new RangeError("Invalid time value");var f=E(I(o),{addSuffix:Boolean(o==null?void 0:o.addSuffix),comparison:O}),N,U;O>0?(N=(0,i.Z)(a),U=(0,i.Z)(r)):(N=(0,i.Z)(r),U=(0,i.Z)(a));var k=$(U,N),B=((0,e.Z)(U)-(0,e.Z)(N))/1e3,g=Math.round((k-B)/60),C;if(g<2)return o!=null&&o.includeSeconds?k<5?u.formatDistance("lessThanXSeconds",5,f):k<10?u.formatDistance("lessThanXSeconds",10,f):k<20?u.formatDistance("lessThanXSeconds",20,f):k<40?u.formatDistance("halfAMinute",0,f):k<60?u.formatDistance("lessThanXMinutes",1,f):u.formatDistance("xMinutes",1,f):g===0?u.formatDistance("lessThanXMinutes",1,f):u.formatDistance("xMinutes",g,f);if(g<45)return u.formatDistance("xMinutes",g,f);if(g<90)return u.formatDistance("aboutXHours",1,f);if(g<t){var z=Math.round(g/60);return u.formatDistance("aboutXHours",z,f)}else{if(g<l)return u.formatDistance("xDays",1,f);if(g<v){var G=Math.round(g/t);return u.formatDistance("xDays",G,f)}else if(g<Z)return C=Math.round(g/v),u.formatDistance("aboutXMonths",C,f)}if(C=M(U,N),C<12){var W=Math.round(g/v);return u.formatDistance("xMonths",W,f)}else{var L=C%12,R=Math.floor(C/12);return L<3?u.formatDistance("aboutXYears",R,f):L<9?u.formatDistance("overXYears",R,f):u.formatDistance("almostXYears",R+1,f)}}},"./js/api/commands/user/email/usage.js":function(j,b,s){s.d(b,{Ic:function(){return m},LP:function(){return p},Lb:function(){return D},TM:function(){return i},gN:function(){return x},zS:function(){return d}});var c=s("./js/api/command/index.js");const i=c.Z.get({id:"BLOCK_CRACKING",url:"/CMD_EMAIL_USAGE",params:{main_info:!1,sending_php_scripts:!1,block_cracking_paths:!0},domain:!0,pagination:!0,after:n=>n.flow(M=>M.block_cracking_paths?M:{block_cracking_paths:"no",block_cracking_paths_table:{info:{ipp:"10",total_pages:"1",current_page:"1",rows:"0"}}},n.moveProp({block_cracking_paths:"options.enabled",block_cracking_paths_table:"rows"}),n.processTableInfo("rows"),n.mapProps({options:n.mapProps({enabled:n.convert.toAppBoolean}),rows:n.flow(n.toArray,n.mapArray(n.flow(n.moveProp({date_blocked:"date",blocked_path:"path"}),n.mapProps({date:n.convert.toAppDate}))))}))}),d=c.Z.get({id:"SENDING_SCRIPTS",url:"/CMD_EMAIL_USAGE",params:{main_info:!1,sending_php_scripts:!0,block_cracking_paths:!1,which:"both"},domain:!0,pagination:!0,after:n=>n.flow(n.moveProp({sending_php_scripts:"rows"}),n.processTableInfo("rows"),n.mapProp("rows",n.flow(n.toArray,n.mapArray(n.flow(n.moveProp({script_name:"script",mail_line_number:"line",send_count:"send"}),n.mapProps({send:n.convert.toAppNumber,line:n.flow(n.convert.toAppString,n.convert.toAppNumber)}))))))}),m=c.Z.get({id:"EMAIL_USAGE",url:"/CMD_EMAIL_USAGE",params:{main_info:!0,sending_php_scripts:!1,block_cracking_paths:!1,which:"both"},schema:{direction:c.Z.OPTIONAL_STRING},domain:!0,pagination:!0,after:n=>n.flow(n.project({rows:"deliveries",highest:"highest"}),n.processTableInfo("rows"),n.mapProp("rows",n.mapArrayProps({time:n.convert.toAppDate,size:n.convert.toAppNumber})))}),D=c.Z.select({url:"/CMD_EMAIL_USAGE",params:{unblock:!0,action:"unblock"},domain:!0}),p=c.Z.get({id:"SMTP_LOG",url:"/CMD_EMAIL_USAGE",params:{action:"smtp_log"},schema:{user:c.Z.REQUIRED_STRING,method:c.Z.REQUIRED_STRING},domain:!0,accept:"text/plain",response:[],after:()=>n=>n.split(`
`)}),x=c.Z.get({id:"EMAIL_USAGE_ID_INFO",url:"/CMD_EMAIL_USAGE",params:{action:"id_info"},schema:{id:c.Z.REQUIRED_STRING},domain:!0,accept:"text/plain",response:[],after:()=>n=>n.split(`
`)})},"./js/composables/dateFilter.ts":function(j,b,s){s.d(b,{W:function(){return D},f:function(){return d.f}});var c=s("../node_modules/ramda/es/index.js"),i=s("../node_modules/date-fns/esm/format/index.js"),d=s("./js/modules/date-formats.ts"),m=s("./js/modules/customizations/date-formats/default.ts");const D=c.WAo((p,x)=>{if(x)try{return(0,i.Z)(x,d.f.value[p])}catch(n){return console.warn(`Given ${p} format is incorrect:
${n.message}`),(0,i.Z)(x,m.d[p])}return""})},"./js/composables/filters.ts":function(j,b,s){s.d(b,{Q0:function(){return $},aS:function(){return E},d5:function(){return y},eB:function(){return S},hT:function(){return M},kC:function(){return n},n9:function(){return A},zM:function(){return w}});var c=s("../node_modules/date-fns/esm/formatDistance/index.js"),i=s("../node_modules/punycode/punycode.es6.js"),d=s("./js/composables/dateFilter.ts"),m=s("./js/composables/gettext.ts");const{$gettext:D,$ngettext:p,$gettextInterpolate:x}=(0,m.Z)(),n=e=>{var t;return e?((t=e.at(0))===null||t===void 0?void 0:t.toUpperCase())+e.slice(1):""},M=(e,t="datetime")=>(0,d.W)(t,e),w=e=>(0,c.Z)(e,new Date),S=(e,t=1024)=>{const l=Number(e);if(!l)return"0 B";const v=["B","KB","MB","GB","TB","PB","EB","ZB","YB"],Z=Math.floor(Math.log(l)/Math.log(t));return`${parseFloat((l/t**Z).toFixed(2))} ${v[Z]}`},T=e=>{try{return(0,i.xX)(e)}catch(t){return e}},A=e=>(0,i.xX)(e),$=e=>{if(!e||!e.includes("@"))return e;const[t,l]=e.split("@");return[t,T(l)].join("@")},y=e=>{if(e<60)return D("less than a minute");const t=Math.floor(e/60)%60,l=Math.floor(e/3600)%24,v=Math.floor(e/(3600*24)),Z=[v?p("%{days} day","%{days} days",v):null,l?p("%{hours} hour","%{hours} hours",l):null,t?p("%{minutes} minute","%{minutes} minutes",t):null].filter(Boolean).join(", ");return x(Z,{days:v,hours:l,minutes:t})},E=(e,t)=>e.length<=t?e:`${e.substring(0,t)}...`,I=()=>({capitalize:n,date:M,distanceFromNow:w,humanReadableSize:S,p6eUnicode:A,p6eUnicodeEmail:$,formatUptime:y,truncateString:E})},"./js/pages/user/email/usage/index.vue":function(j,b,s){s.r(b),s.d(b,{default:function(){return E}});var c=function(){var e=this,t=e._self._c;return t("app-page",{scopedSlots:e._u([{key:"default",fn:function(){return[t("app-page-section",[t("div",{directives:[{name:"flex",rawName:"v-flex",value:{dir:e.clientStore.isPhone?"column":"row",cross:e.clientStore.isPhone?"start":"center"},expression:`{
                    dir: clientStore.isPhone ? 'column' : 'row',
                    cross: clientStore.isPhone ? 'start' : 'center',
                }`},{name:"gutter",rawName:"v-gutter",value:[1,1],expression:"[1, 1]"}]},[t("span",{staticClass:"txt:bold",style:{minWidth:"11rem"},domProps:{textContent:e._s(e.$gettext("Show Usage From:"))}}),e._v(" "),t("input-radio",{attrs:{value:"today"},model:{value:e.showFrom,callback:function(l){e.showFrom=l},expression:"showFrom"}},[t("span",{domProps:{textContent:e._s(e.$gettext("Today"))}})]),e._v(" "),t("input-radio",{attrs:{value:"past"},model:{value:e.showFrom,callback:function(l){e.showFrom=l},expression:"showFrom"}},[t("span",{domProps:{textContent:e._s(e.$gettext("This Month (excluding today)"))}})]),e._v(" "),t("input-radio",{attrs:{value:"both"},model:{value:e.showFrom,callback:function(l){e.showFrom=l},expression:"showFrom"}},[t("span",{domProps:{textContent:e._s(e.$gettext("This Month"))}})])],1),e._v(" "),t("div",{directives:[{name:"flex",rawName:"v-flex",value:{dir:e.clientStore.isPhone?"column":"row",cross:e.clientStore.isPhone?"start":"center"},expression:`{
                    dir: clientStore.isPhone ? 'column' : 'row',
                    cross: clientStore.isPhone ? 'start' : 'center',
                }`},{name:"gutter",rawName:"v-gutter",value:[null,1],expression:"[null, 1]"}]},[t("span",{directives:[{name:"margin",rawName:"v-margin",value:[1,0,0,0],expression:"[1, 0, 0, 0]"}],staticClass:"txt:bold",style:{minWidth:"11rem"},domProps:{textContent:e._s(e.$gettext("Direction:"))}}),e._v(" "),t("input-radio",{attrs:{value:"outgoing",model:e.direction},on:{change:e.toggleDirection}},[t("span",{domProps:{textContent:e._s(e.$gettext("Outgoing"))}})]),e._v(" "),t("input-radio",{attrs:{value:"incoming",model:e.direction},on:{change:e.toggleDirection}},[t("span",{domProps:{textContent:e._s(e.$gettext("Incoming"))}})])],1)]),e._v(" "),e.direction==="outgoing"?t("app-page-section",[t("ui-r-table",{attrs:{"is-checkable":!1,rows:e.totalUsage,"disable-pagination":"","is-sortable":!1,editable:!1,columns:[{id:"label",label:e.$gettext("Highest")},{id:"value",label:e.$gettext("Value")},{id:"count",label:e.$gettext("Count")},{id:"percent",label:e.$gettext("Percent")}],"vertical-layout":e.clientStore.isPhone},scopedSlots:e._u([{key:"col:label",fn:function({label:l,tooltip:v}){return[t("ui-tooltip",{attrs:{theme:"safe"},scopedSlots:e._u([{key:"trigger",fn:function(){return[t("span",{staticClass:"txt:bold cursor:pointer"},[e._v(`
                                `+e._s(l)+`
                                `),t("ui-icon",{attrs:{id:"question",theme:"safe",size:"medium"}})],1)]},proxy:!0}],null,!0)},[e._v(`
                        `+e._s(v)+`
                    `)])]}},{key:"table:after",fn:function(){return[t("span",{domProps:{textContent:e._s(e.$gettext("Note: For older exim.pl files before version 13, each delivery attempt is counted, including retries."))}})]},proxy:!0}],null,!1,3786105972)})],1):e._e(),e._v(" "),t("app-page-section",[t("ui-api-table",e._b({ref:"table",attrs:{"disable-select":"","vertical-layout":e.clientStore.isPhone},scopedSlots:e._u([{key:"col:id",fn:function({id:l}){return[t("ui-link",{on:{click:function(v){return e.showIdInfo(l)}}},[e._v(`
                        `+e._s(l)+`
                    `)])]}},{key:"col:time",fn:function({time:l}){return[e._v(`
                    `+e._s(e.date(l,"datetime"))+`
                `)]}},{key:"col:size",fn:function({size:l}){return[e._v(`
                    `+e._s(e.humanReadableSize(l))+`
                `)]}}])},"ui-api-table",{command:e.$commands.getUsage,columns:{time:e.$gettext("Time"),sender:{label:e.$gettext("Sender"),searchable:!0},authenticated_id:{label:e.$gettext("Authentication"),searchable:!0},sender_host_address:{label:e.$gettext("Sender Host"),searchable:!0},size:e.$gettext("Size"),destination:{label:e.$gettext("Destination"),searchable:!0},path:{label:e.$gettext("Path"),searchable:!0},id:e.$gettext("ID")},requestData:{direction:e.direction,which:e.showFrom}},!1))],1),e._v(" "),t("id-info-dialog")]},proxy:!0},{key:"bottom:links",fn:function(){return[e.$api.blockCracking?t("ui-link",{attrs:{name:"user/email/usage/blockcracking",bullet:""}},[t("span",{domProps:{textContent:e._s(e.$gettext("BlockCracking Blocked Paths"))}})]):e._e(),e._v(" "),t("ui-link",{attrs:{name:"user/email/usage/php-scripts",bullet:""}},[t("span",{domProps:{textContent:e._s(e.$gettext("PHP Scripts"))}})])]},proxy:!0}])})},i=[],d=s("./js/stores/index.ts"),m=s("./js/api/commands/user/email/usage.js"),D=function(){var e=this,t=e._self._c;return t("ui-dialog",{attrs:{id:"ID_INFO_DIALOG","no-close-btn":"",size:"normal",title:e.$gettext("ID Info")},scopedSlots:e._u([{key:"content",fn:function(){return[t("ui-pre",{attrs:{"content-lines":e.$api.info}})]},proxy:!0}])})},p=[],x={api:[{command:m.gN,bind:"info"}]},n=x,M=s("../node_modules/vue-loader/lib/runtime/componentNormalizer.js"),w=(0,M.Z)(n,D,p,!1,null,null,null),S=w.exports,T=s("./js/composables/filters.ts"),A={components:{IdInfoDialog:S},preload:[({direction:I="outgoing"})=>(0,m.Ic)({direction:I}),m.TM],api:[{command:m.Ic,bind:{"response.highest":"highest"}},{command:m.TM,bind:{"response.options.enabled":"blockCracking"}}],props:{direction:{type:String,required:!1,default:"outgoing"}},commands:{getUsage:m.Ic},data:()=>({showFrom:"both"}),computed:{totalUsage(){return[{label:this.$gettext("Sender"),tooltip:this.$gettext('The "From" value set in the email header. This value should not be considered as accurate, as a sender can specify any value they wish.'),...this.$api.highest.sender},{label:this.$gettext("Authentication"),tooltip:this.$gettext("If SMTP authentication is used, this will show the login name used. Scripts will show the owner of the script. Can be considered accurate."),...this.$api.highest.authenticated_id},{label:this.$gettext("Sender Host"),tooltip:this.$gettext("If this is set, it will show the IP that connect to the server. If no IP is set, then the email was sent vie a local script."),...this.$api.highest.sender_host_address},{label:this.$gettext("Path"),tooltip:this.$gettext('If the email was generated from a script, the path value will show the working directory the script was in. An email in the spool will have a path value of "retry" for each attempt.'),...this.$api.highest.php_script}]},...(0,d.Kc)(["client"])},methods:{date:T.hT,humanReadableSize:T.eB,toggleDirection(I){this.$router.push({name:"user/email/usage",params:{direction:I}})},async showIdInfo(I){await(0,m.gN)({id:I}),this.$dialog("ID_INFO_DIALOG").open()}}},$=A,y=(0,M.Z)($,c,i,!1,null,null,null),E=y.exports}}]);