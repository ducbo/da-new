(self.webpackChunk=self.webpackChunk||[]).push([[353,8952],{"./js/api/commands/reseller/backup.js":function(h,d,n){"use strict";n.d(d,{Fi:function(){return e},Gw:function(){return P},Q0:function(){return I},VP:function(){return v},dO:function(){return x},dh:function(){return m},fz:function(){return S},hd:function(){return f},ld:function(){return p},o7:function(){return r},pZ:function(){return O},pi:function(){return o},v6:function(){return u}});var t=n("./js/api/command/index.js");const i="/CMD_USER_BACKUP",p=t.Z.get({id:"USER_BACKUPS",url:i,after:s=>s.flow(a=>({rows:a.crons,location:a.files_location}),s.processTableInfo("rows"),s.mapProps({rows:s.flow(s.toArray,s.mapArrayProps({where:s.flow(s.moveProp("encryption_password","encrypted"),s.mapProps({encrypted:s.flow(s.setDefault("0"),s.isEqual("1")),path:a=>a.replace("<span class='green_lock'>&#128274;</span>","").trim()}))}))}))}),l=t.Z.get({id:"HAS_USER_BACKUPS",url:i,response:!1,mapResponse:s=>s.crons.length!==0}),u=t.Z.get({id:"BACKUP_ENCRYPTION_STATUS",url:i,after:s=>s.flow(s.project({enabled:"settings.allow_backup_encryption",password:"settings.encryption_password"}),s.mapProp("enabled",s.convert.toAppBoolean))}),f=t.Z.select({url:i,params:{duplicate:!0}}),m=t.Z.select({url:i,params:{delete:!0}}),v=t.Z.post({url:i,params:{action:"setting"},schema:{message:t.Z.REQUIRED_BOOL,local_ns:t.Z.REQUIRED_BOOL,restore_spf:t.Z.REQUIRED_BOOL}}),P=t.Z.get({id:"USER_BACKUP_SETTINGS",url:i,after:s=>s.flow(s.project({local_ns:"settings.local_ns",message:"settings.message",restore_spf:"settings.restore_spf"}),s.mapValues(s.convert.toAppBoolean))}),x=t.Z.get({id:"USER_BACKUP_SCHEDULE_OPTIONS",url:i,after:s=>s.flow(s.project({settings:"settings","settings.append":"append_to_path",where:"where",users:"users",location:"files_location"}),s.mapProps({users:s.flow(s.deleteProp("info"),s.toArray,s.mapArray(s.getProp("user"))),settings:s.flow(s.project({ip:"ftp_ip",password:"ftp_password",path:"ftp_path",port:"ftp_port",secure:"ftp_secure",username:"ftp_username",append:"append"}),s.mapProps({secure:s.convert.toAppBoolean,append:a=>{const c=Object.values(a),_=c.find(y=>y.selected),g=(y,w)=>({...y,[w.value]:w.text}),j=c.reduce(g,{});return{value:_.value,options:j}}}))}))}),O=t.Z.get({id:"USER_BACKUP_RESTORE_OPTIONS",url:i,after:s=>s.flow(s.project({settings:"settings",where:"where",location:"files_location",ips:"ip_list",files:"files"}),s.mapProps({files:s.flow(s.deleteProp("info"),s.toArray),settings:s.flow(s.getProps(["ftp_ip","ftp_password","ftp_path","ftp_port","ftp_secure","ftp_username"]),s.mapProps({ftp_secure:s.convert.toAppBoolean})),ips:a=>{const c=Object.values(a),_=c.find(y=>y.selected),g=(y,w)=>({...y,[w.value]:w.text}),j=c.reduce(g,{});return{value:_.value,options:j}}}))}),S=t.Z.post({url:i,params:{action:"create",form_version:"3"},schema:{who:t.Z.REQUIRED_STRING,select:{type:Array,required:!1},skip_suspended:t.Z.OPTIONAL_BOOL,when:t.Z.REQUIRED_STRING,minute:t.Z.OPTIONAL_STRING,hour:t.Z.OPTIONAL_STRING,dayofmonth:t.Z.OPTIONAL_STRING,month:t.Z.OPTIONAL_STRING,dayofweek:t.Z.OPTIONAL_STRING,where:t.Z.REQUIRED_STRING,ftp_ip:t.Z.OPTIONAL_STRING,ftp_username:t.Z.OPTIONAL_STRING,ftp_password:t.Z.OPTIONAL_STRING,ftp_path:t.Z.OPTIONAL_STRING,ftp_port:t.Z.OPTIONAL_STRING,ftp_secure:t.Z.OPTIONAL_STRING,append_to_path:t.Z.OPTIONAL_STRING,custom_append:t.Z.OPTIONAL_STRING,encryption_password:t.Z.OPTIONAL_STRING}}),e=t.Z.get({url:i,id:"USER_BACKUP_RESTORE_FILES",params:{action:"update_files"},schema:{where:t.Z.REQUIRED_STRING,ftp_ip:t.Z.OPTIONAL_STRING,ftp_username:t.Z.OPTIONAL_STRING,ftp_password:t.Z.OPTIONAL_STRING,ftp_path:t.Z.OPTIONAL_STRING,ftp_port:t.Z.OPTIONAL_STRING,ftp_secure:t.Z.OPTIONAL_STRING},after:s=>s.flow(s.getProp("files"),s.deleteProp("info"),s.toArray)}),o=t.Z.post({url:i,params:{action:"restore"},schema:{where:t.Z.REQUIRED_STRING,ftp_ip:t.Z.OPTIONAL_STRING,ftp_username:t.Z.OPTIONAL_STRING,ftp_password:t.Z.OPTIONAL_STRING,ftp_path:t.Z.OPTIONAL_STRING,ftp_port:t.Z.OPTIONAL_STRING,ftp_secure:t.Z.OPTIONAL_STRING,ip_choice:t.Z.REQUIRED_STRING,ip:t.Z.OPTIONAL_STRING,select:{type:Array,required:!0},encryption_password:t.Z.OPTIONAL_STRING}}),r=t.Z.post({url:"/CMD_USER_BACKUP_MODIFY",id:"USER_BACKUP_CRON",schema:{id:t.Z.REQUIRED_STRING},notifySuccess:!1,notifyError:!0,after:s=>s.flow(s.moveProp({append_to_path:"append","settings.where":"where"}),s.mapProps({settings:s.mapProp("ftp_secure",s.convert.toAppBoolean),who:s.mapProps({skip_suspended:s.convert.toAppBoolean,users:s.flow(s.deleteProp("info"),s.toArray,s.mapArray(s.getProp("user"))),select:s.feedWith(1,s.flow(s.getProp("users"),s.deleteProp("info"),s.filter(s.flow(s.getProp("checkbox"),s.isEqual("checked"))),s.mapValues(s.getProp("user")),s.toArray))}),append:s.flow(s.mapProps({options:s.feedWith(1,s.transformObject(({value:a,text:c})=>({[a]:c}))),value:s.feedWith(1,s.flow(s.find(s.getProp("selected")),s.getProp("value")))}),s.getProps(["value","options"])),custom_append:s.feedWith(1,s.getProp("append.custom_append"))}))}),I=t.Z.post({url:i,params:{action:"modify",when:"cron",form_version:"3"},schema:{id:t.Z.REQUIRED_STRING,who:t.Z.REQUIRED_STRING,select:{type:Array,required:!1},skip_suspended:t.Z.OPTIONAL_BOOL,minute:t.Z.REQUIRED_STRING,hour:t.Z.REQUIRED_STRING,dayofmonth:t.Z.REQUIRED_STRING,month:t.Z.REQUIRED_STRING,dayofweek:t.Z.REQUIRED_STRING,where:t.Z.REQUIRED_STRING,ftp_ip:t.Z.OPTIONAL_STRING,ftp_username:t.Z.OPTIONAL_STRING,ftp_password:t.Z.OPTIONAL_STRING,ftp_path:t.Z.OPTIONAL_STRING,ftp_port:t.Z.OPTIONAL_STRING,ftp_secure:t.Z.OPTIONAL_STRING,append_to_path:t.Z.REQUIRED_STRING,custom_append:t.Z.OPTIONAL_STRING}})},"./js/vue-globals/mixins.js":function(h,d,n){"use strict";n.r(d),n.d(d,{$bindTab:function(){return s},$clickOutside:function(){return e},$resizeListener:function(){return I},$scrollListener:function(){return o}});var t=n("../node_modules/vue/dist/vue.common.prod.js"),i=n.n(t),p=n("../node_modules/ramda/es/index.js"),l=n("./js/modules/file.js"),u=n("./js/modules/utils/index.js"),f=n("./js/modules/constants.js"),m=n("./js/modules/utils/css.js"),v=n("../node_modules/punycode/punycode.es6.js"),P=n("./js/vue-globals/helpers.js"),x=n("./js/stores/index.ts");const O=n("./js/vue-globals/mixins sync recursive \\.js$");(0,l.s)(O,a=>i().mixin(a.module)),i().mixin({data:()=>({isMounted:!1}),mounted(){this.isMounted=!0}}),i().mixin({methods:{$dialog(a){return{open:()=>P.uY.emit("dialog:open",a),close:()=>P.uY.emit("dialog:close",a)}}}}),i().mixin({computed:{$domain(){return this.$_ctx.session.domain},$domainUnicode(){return v.ZP.toUnicode(this.$domain)}}}),i().mixin({beforeCreate(){const a=(0,x.oR)(PiniaStores.VALIDATION);this.$valid=a.isValid.bind(a)}}),i().mixin({created(){this.regexps=f.gk}}),i().mixin({computed:{$p6e(){const a=c=>_=>{try{return c(_)}catch(g){return _}};return{toA:a(v.ZP.toASCII),toU:a(v.ZP.toUnicode),email2ascii:c=>{if(!c||!c.includes("@"))return c;const[_,g]=c.split("@");return[_,v.ZP.toASCII(g)].join("@")},email2unicode:c=>{if(!c||!c.includes("@"))return c;const[_,g]=c.split("@");return[_,v.ZP.toUnicode(g)].join("@")}}}}}),i().mixin({computed:{$_layout:(0,P.YM)("skin/layout")}}),i().mixin({methods:{$_useStore(a){return(0,x.oR)(a)}}});const S=[];document.body.addEventListener("click",a=>{S.forEach(c=>c(a.target))}),window.addEventListener("touchmove",a=>{S.forEach(c=>c(a.target))});const e={methods:{$clickOutsideListener(a,c){const _=j=>p.zGw(p.Bxt(c),p.qhW(Array.isArray,y=>[y]),p.hXT(p.CyQ(p.kKJ)),p.YPD(y=>y===j||y.contains(j)))(),g=j=>{_(j)&&this.$emit(`clickOutside:${a}`)};S.push(g)}}},o={methods:{__getScroller(){return this.$_layout==="sidebar"?window.document.querySelector("main"):window},__emitScroll(){this.$emit("window:scroll",window.pageYOffset)}},mounted(){const a=this.__getScroller();a&&a.addEventListener("scroll",this.__emitScroll)},destroyed(){const a=this.__getScroller();a&&a.removeEventListener("scroll",this.__emitScroll)}},r=[];window.addEventListener("resize",()=>{r.forEach(a=>a())});const I={created(){this.$resizeListener=()=>{this.$emit("window:resize",window.innerWidth)},r.push(this.$resizeListener)},destroyed(){r.splice(r.indexOf(this.$resizeListener),1)}},s=({param:a="tab",defaultTab:c}={param:"tab"})=>({computed:{[a]:{get(){return this.$route.params[a]||c},set(_){this.$route.params[a]!==_&&this.$router.replace(u._.merge({},this.$route,{params:{[a]:_}}))}}}})},"./js/vue-globals/mixins/bindApi.js":function(h,d,n){"use strict";n.r(d);var t=n("../node_modules/ramda/es/index.js");const i=(p,l)=>t.ETc(p.split("."),l);d.default={beforeCreate(){this.$options.commands&&(this.$commands=this.$options.commands)},computed:{$api(){if(!this.$options.api)return[];const p=this.$options.api;return typeof p=="function"?p.data.response:t.u4g((u,{command:f,bind:m})=>{if(typeof m=="string")return{...u,[m]:f.data.response};const v=t.u4g((P,[x,O])=>{const S=x.includes(".")?i(x,f.data):f.data[x]||f.data.response[x];return{...P,[O]:S}},{},t.Zpf(m));return{...u,...v}},{},p)}}}},"./js/vue-globals/mixins/local/clickOutside.js":function(h,d,n){"use strict";n.r(d),n.d(d,{$clickOutside:function(){return l}});var t=n("../node_modules/ramda/es/index.js");const i=[];document.body.addEventListener("click",u=>{i.forEach(t.gH4(u))}),window.addEventListener("touchstart",u=>{i.forEach(t.gH4(u))});const p=(u,f)=>t.zGw(t.qhW(Array.isArray,m=>[m]),t.hXT(t.CyQ(t.kKJ)),t.YPD(m=>m===u||m.contains(u)))(f),l={methods:{$clickOutsideListener(u,f){const m=v=>{p(v.target,f)&&this.$emit(`clickOutside:${u}`)};i.push(m)}}}},"./js/vue-globals/mixins/local/inputValidation.js":function(h,d,n){"use strict";n.r(d),n.d(d,{$inputValidation:function(){return p}});var t=n("./js/vue-globals/helpers.js"),i=n("./js/stores/index.ts");const p={inject:{groupID:{default:null},inputID:{default:null},validators:{default:()=>({})}},props:{id:{type:String,required:!1,default(){return this.inputID}},group:{type:String,required:!1,default(){return this.groupID}},novalidate:{type:Boolean,required:!1,default(){return!Object.keys(this.validators).length}}},computed:{validationStore(){return(0,i.oR)(PiniaStores.VALIDATION)},valid(){return this.validationStore.isValid(this.group,this.id)},errorState(){return!this.novalidate&&this.isUpdated&&!this.valid},isUpdated(){var l;const u=(l=this.validationStore.groups[this.group])==null?void 0:l[this.id];return typeof u=="undefined"?!1:u.updated}},methods:{$validate(l){this.id&&!this.novalidate&&this.validationStore.validate(this.groupID,this.id,l,this.validators)}},created(){if(!this.novalidate){const{validate:l}=this.$options;l&&this.$watch(l,(0,t.Ds)(this.$validate,{trailing:!0,leading:!1,delay:200}),{immediate:!0})}},destroyed(){this.novalidate||this.validationStore.deleteInput(this.group,this.id)}}},"./js/vue-globals/mixins/notification.js":function(h,d,n){"use strict";n.r(d);var t=n("./js/composables/index.ts");d.default={created(){const i=new t.d$;this.$notifications=i}}},"./js/vue-globals/mixins/reloadApiTable.js":function(h,d,n){"use strict";n.r(d);var t=n("./js/modules/constants.js");const i=l=>l.$options&&l.$options.name==="UiApiTable",p=l=>{const u=[l];let f=l;for(;f=u.shift();){if(i(f))return f;f.$children.length&&u.push(...f.$children)}return!1};d.default={methods:{$reloadApiTable({reset:l=!0}={}){const u=p(this);if(!u){t.Vi.DEV&&console.warn("$reloadApiTable called without any ui-api-table child");return}u.reloadTable(),l&&Object.assign(this.$data,this.$options.data.apply(this))}}}},"./js/vue-globals/mixins/session.js":function(h,d,n){"use strict";n.r(d);var t=n("./js/context/index.ts");d.default={computed:{$_ctx(){return t.T},$_flags(){return t.T.session.features},$_session(){return t.T.session.allValues}},methods:{$_cmd(i){return t.T.session.allowedCommands.includes(i)}}}},"./js/vue-globals/mixins/staticData.js":function(h,d,n){"use strict";n.r(d),d.default={created(){this.$options.staticData&&Object.entries(this.$options.staticData).forEach(([t,i])=>{this[t]=typeof i=="function"?i.bind(this)():i})}}},"../node_modules/mini-css-extract-plugin/dist/loader.js??clonedRuleSet-13.use[1]!../node_modules/css-loader/dist/cjs.js??clonedRuleSet-13.use[2]!../node_modules/vue-loader/lib/loaders/stylePostLoader.js!../node_modules/postcss-loader/dist/cjs.js??clonedRuleSet-13.use[3]!../node_modules/sass-loader/dist/cjs.js??clonedRuleSet-13.use[4]!../node_modules/vue-loader/lib/index.js??vue-loader-options!../node_modules/unplugin/dist/webpack/loaders/transform.js?unpluginName=unplugin-vue-define-options!./js/pages/reseller/backups/modify.vue?vue&type=style&index=0&id=e4a8e124&prod&lang=scss&scoped=true&":function(){},"./js/pages/reseller/backups/modify.vue":function(h,d,n){"use strict";n.r(d),n.d(d,{default:function(){return O}});var t=function(){var e=this,o=e._self._c;return o("app-page",{attrs:{id:"modify-reseller-backup"},scopedSlots:e._u([{key:"default",fn:function(){return[o("app-page-section",[o("ui-steps",{attrs:{steps:[{id:"who",label:e.$gettext("Step 1: Who"),desc:e.$gettext("Select users you would like to backup."),completed:e.validWho},{id:"when",label:e.$gettext("Step 2: When"),desc:e.$gettext("Select time period for backup."),completed:e.validWhen},{id:"where",label:e.$gettext("Step 3: Where"),desc:e.$gettext("Select directory for backups."),completed:e.validWhere}],current:e.step,disabled:!e.$valid("modifyBackup")},on:{"update:current":function(r){e.step=r}},scopedSlots:e._u([{key:"step:who",fn:function(){return[o("div",{key:"who"},[o("ui-form-element",{attrs:{"vertical-on-phone":!1,reverse:e.clientStore.isPhone},scopedSlots:e._u([{key:"title",fn:function(){return[o("span",{domProps:{textContent:e._s(e.$gettext("All Users"))}})]},proxy:!0},{key:"content",fn:function(){return[o("input-radio",{attrs:{value:"all"},model:{value:e.who,callback:function(r){e.who=r},expression:"who"}})]},proxy:!0}])}),e._v(" "),o("ui-form-element",{attrs:{"vertical-on-phone":!1,reverse:e.clientStore.isPhone},scopedSlots:e._u([{key:"title",fn:function(){return[o("span",{domProps:{textContent:e._s(e.$gettext("Selected Users"))}})]},proxy:!0},{key:"content",fn:function(){return[o("input-radio",{attrs:{value:"selected"},model:{value:e.who,callback:function(r){e.who=r},expression:"who"}})]},proxy:!0}])}),e._v(" "),o("ui-form-element",{attrs:{"vertical-on-phone":!1,reverse:e.clientStore.isPhone},scopedSlots:e._u([{key:"title",fn:function(){return[o("span",{domProps:{textContent:e._s(e.$gettext("All Users Except Selected"))}})]},proxy:!0},{key:"content",fn:function(){return[o("input-radio",{attrs:{value:"except"},model:{value:e.who,callback:function(r){e.who=r},expression:"who"}})]},proxy:!0}])}),e._v(" "),e.who!=="all"?o("ui-form-element",{scopedSlots:e._u([{key:"title",fn:function(){return[o("span",{domProps:{textContent:e._s(e.$gettext("Users"))}})]},proxy:!0},{key:"content",fn:function(){return[o("input-select-multiple",{attrs:{options:e.$api.cron.who.users},model:{value:e.whoData.select,callback:function(r){e.$set(e.whoData,"select",r)},expression:"whoData.select"}})]},proxy:!0}],null,!1,3296027937)}):e._e(),e._v(" "),o("ui-form-element",{attrs:{underline:!1,"vertical-on-phone":!1,reverse:e.clientStore.isPhone},scopedSlots:e._u([{key:"title",fn:function(){return[o("span",{domProps:{textContent:e._s(e.$gettext("Skip Suspended"))}})]},proxy:!0},{key:"content",fn:function(){return[o("input-checkbox",{model:{value:e.whoData.skip_suspended,callback:function(r){e.$set(e.whoData,"skip_suspended",r)},expression:"whoData.skip_suspended"}})]},proxy:!0}])})],1)]},proxy:!0},{key:"step:when",fn:function(){return[o("div",{key:"when"},[o("ui-form-element",{attrs:{group:"modifyBackup",validators:{required:!0}},scopedSlots:e._u([{key:"title",fn:function(){return[o("span",{domProps:{textContent:e._s(e.$gettext("Minute"))}})]},proxy:!0},{key:"tooltip",fn:function(){return[o("span",[e._v("0\u201359")])]},proxy:!0},{key:"content",fn:function(){return[o("input-text",{model:{value:e.cron.minute,callback:function(r){e.$set(e.cron,"minute",r)},expression:"cron.minute"}})]},proxy:!0}])}),e._v(" "),o("ui-form-element",{attrs:{group:"modifyBackup",validators:{required:!0}},scopedSlots:e._u([{key:"title",fn:function(){return[o("span",{domProps:{textContent:e._s(e.$gettext("Hour"))}})]},proxy:!0},{key:"tooltip",fn:function(){return[o("span",[e._v("0\u201323")])]},proxy:!0},{key:"content",fn:function(){return[o("input-text",{model:{value:e.cron.hour,callback:function(r){e.$set(e.cron,"hour",r)},expression:"cron.hour"}})]},proxy:!0}])}),e._v(" "),o("ui-form-element",{attrs:{group:"modifyBackup",validators:{required:!0}},scopedSlots:e._u([{key:"title",fn:function(){return[o("span",{domProps:{textContent:e._s(e.$gettext("Day of Month"))}})]},proxy:!0},{key:"tooltip",fn:function(){return[o("span",[e._v("1\u201331")])]},proxy:!0},{key:"content",fn:function(){return[o("input-text",{model:{value:e.cron.dayofmonth,callback:function(r){e.$set(e.cron,"dayofmonth",r)},expression:"cron.dayofmonth"}})]},proxy:!0}])}),e._v(" "),o("ui-form-element",{attrs:{group:"modifyBackup",validators:{required:!0}},scopedSlots:e._u([{key:"title",fn:function(){return[o("span",{domProps:{textContent:e._s(e.$gettext("Month"))}})]},proxy:!0},{key:"tooltip",fn:function(){return[o("span",[e._v("1\u201312")])]},proxy:!0},{key:"content",fn:function(){return[o("input-text",{model:{value:e.cron.month,callback:function(r){e.$set(e.cron,"month",r)},expression:"cron.month"}})]},proxy:!0}])}),e._v(" "),o("ui-form-element",{attrs:{group:"modifyBackup",validators:{required:!0},underline:!1},scopedSlots:e._u([{key:"title",fn:function(){return[o("span",{domProps:{textContent:e._s(e.$gettext("Day of Week"))}})]},proxy:!0},{key:"tooltip",fn:function(){return[o("span",{domProps:{textContent:e._s(e.$gettext("0\u20137; 0,7 = Sunday"))}})]},proxy:!0},{key:"content",fn:function(){return[o("input-text",{model:{value:e.cron.dayofweek,callback:function(r){e.$set(e.cron,"dayofweek",r)},expression:"cron.dayofweek"}})]},proxy:!0}])})],1)]},proxy:!0},{key:"step:where",fn:function(){return[o("div",{key:"where"},[o("ui-form-element",{attrs:{"vertical-on-phone":!1,reverse:e.clientStore.isPhone},scopedSlots:e._u([{key:"title",fn:function(){return[o("span",{domProps:{textContent:e._s(e.$gettextInterpolate(e.$gettext("Local: %{ local_path }"),{local_path:e.$api.cron.settings.local_path}))}})]},proxy:!0},{key:"content",fn:function(){return[o("input-radio",{attrs:{value:"local"},model:{value:e.where,callback:function(r){e.where=r},expression:"where"}})]},proxy:!0}])}),e._v(" "),o("ui-form-element",{attrs:{"vertical-on-phone":!1,reverse:e.clientStore.isPhone},scopedSlots:e._u([{key:"title",fn:function(){return[o("span",{domProps:{textContent:e._s(e.$gettext("FTP"))}})]},proxy:!0},{key:"content",fn:function(){return[o("input-radio",{attrs:{value:"ftp"},model:{value:e.where,callback:function(r){e.where=r},expression:"where"}})]},proxy:!0}])}),e._v(" "),e.where==="ftp"?o("ui-form-element",{scopedSlots:e._u([{key:"title",fn:function(){return[o("span",{domProps:{textContent:e._s(e.$gettext("FTP Settings"))}})]},proxy:!0},{key:"content",fn:function(){return[o("div",[o("ui-form-element",{scopedSlots:e._u([{key:"title",fn:function(){return[o("span",{domProps:{textContent:e._s(e.$gettext("IP"))}})]},proxy:!0},{key:"content",fn:function(){return[o("input-text",{model:{value:e.ftp.ftp_ip,callback:function(r){e.$set(e.ftp,"ftp_ip",r)},expression:"ftp.ftp_ip"}})]},proxy:!0}],null,!1,2732379478)}),e._v(" "),o("ui-form-element",{scopedSlots:e._u([{key:"title",fn:function(){return[o("span",{domProps:{textContent:e._s(e.$gettext("Username"))}})]},proxy:!0},{key:"content",fn:function(){return[o("input-text",{model:{value:e.ftp.ftp_username,callback:function(r){e.$set(e.ftp,"ftp_username",r)},expression:"ftp.ftp_username"}})]},proxy:!0}],null,!1,2698076406)}),e._v(" "),o("ui-form-element",{scopedSlots:e._u([{key:"title",fn:function(){return[o("span",{domProps:{textContent:e._s(e.$gettext("Password"))}})]},proxy:!0},{key:"content",fn:function(){return[o("input-password",{model:{value:e.ftp.ftp_password,callback:function(r){e.$set(e.ftp,"ftp_password",r)},expression:"ftp.ftp_password"}})]},proxy:!0}],null,!1,3364507540)}),e._v(" "),o("ui-form-element",{scopedSlots:e._u([{key:"title",fn:function(){return[o("span",{domProps:{textContent:e._s(e.$gettext("Remote Path"))}})]},proxy:!0},{key:"content",fn:function(){return[o("input-text",{model:{value:e.ftp.ftp_path,callback:function(r){e.$set(e.ftp,"ftp_path",r)},expression:"ftp.ftp_path"}})]},proxy:!0}],null,!1,3471260882)}),e._v(" "),o("ui-form-element",{scopedSlots:e._u([{key:"title",fn:function(){return[o("span",{domProps:{textContent:e._s(e.$gettext("Port"))}})]},proxy:!0},{key:"content",fn:function(){return[o("input-text",{model:{value:e.ftp.ftp_port,callback:function(r){e.$set(e.ftp,"ftp_port",r)},expression:"ftp.ftp_port"}})]},proxy:!0}],null,!1,2598081206)}),e._v(" "),o("ui-form-element",{attrs:{"vertical-on-phone":!1,reverse:e.clientStore.isPhone},scopedSlots:e._u([{key:"title",fn:function(){return[o("span",{domProps:{textContent:e._s(e.$gettext("Secure FTP"))}})]},proxy:!0},{key:"content",fn:function(){return[o("input-checkbox",{model:{value:e.ftp.ftp_secure,callback:function(r){e.$set(e.ftp,"ftp_secure",r)},expression:"ftp.ftp_secure"}})]},proxy:!0}],null,!1,3032363706)})],1)]},proxy:!0}],null,!1,693698650)}):e._e(),e._v(" "),o("ui-form-element",{attrs:{underline:e.$api.encryption||e.append_to_path==="custom"},scopedSlots:e._u([{key:"title",fn:function(){return[o("span",{domProps:{textContent:e._s(e.$gettext("Append"))}})]},proxy:!0},{key:"content",fn:function(){return[o("input-select",{attrs:{options:e.$api.cron.append.options},model:{value:e.append_to_path,callback:function(r){e.append_to_path=r},expression:"append_to_path"}})]},proxy:!0}])}),e._v(" "),e.append_to_path==="custom"?o("ui-form-element",{attrs:{"path-segment":"directadmin/backup-restore-migration/backups.html#custom-append-values-in-backup-path",underline:e.$api.encryption},scopedSlots:e._u([{key:"title",fn:function(){return[o("span",{domProps:{textContent:e._s(e.$gettext("Custom Path"))}})]},proxy:!0},{key:"content",fn:function(){return[o("input-text",{directives:[{name:"margin",rawName:"v-margin",value:[1,0],expression:"[1, 0]"}],attrs:{prefix:"/"},model:{value:e.custom_append,callback:function(r){e.custom_append=r},expression:"custom_append"}})]},proxy:!0}],null,!1,2428725859)}):e._e(),e._v(" "),e.$api.encryption?[o("ui-form-element",{attrs:{underline:e.encrypt,"vertical-on-phone":!1,reverse:e.clientStore.isPhone},scopedSlots:e._u([{key:"title",fn:function(){return[o("span",{domProps:{textContent:e._s(e.$gettext("Backup Encryption"))}})]},proxy:!0},{key:"content",fn:function(){return[o("input-checkbox",{model:{value:e.encrypt,callback:function(r){e.encrypt=r},expression:"encrypt"}})]},proxy:!0}],null,!1,769703515)}),e._v(" "),o("transition",{attrs:{name:"fadeBounce"}},[e.encrypt?o("ui-form-element",{attrs:{group:"modifyBackup",validators:{required:!0},underline:!1},scopedSlots:e._u([{key:"title",fn:function(){return[o("span",{domProps:{textContent:e._s(e.$gettext("Password"))}})]},proxy:!0},{key:"content",fn:function(){return[o("input-password",{model:{value:e.password,callback:function(r){e.password=r},expression:"password"}})]},proxy:!0}],null,!1,3464064881)}):e._e()],1)]:e._e()],2)]},proxy:!0},{key:"buttons",fn:function(){return[o("ui-button",{attrs:{theme:"primary",disabled:!(e.validWho&&e.validWhen&&e.validWhere)},on:{click:e.submit}},[o("span",{domProps:{textContent:e._s(e.$gettext("Save"))}})])]},proxy:!0}])})],1)]},proxy:!0}])})},i=[],p=n("./js/stores/index.ts"),l=n("./js/vue-globals/mixins.js"),u=n("./js/api/commands/reseller/backup.js"),f={preload:[u.o7,u.v6],api:[{command:u.o7,bind:"cron"},{command:u.v6,bind:{"response.enabled":"encryption",response:"encryptionStatus"}}],mixins:[(0,l.$bindTab)({defaultTab:"who",param:"step"})],props:{id:{type:String,required:!0}},data:()=>({who:"all",where:"local",whoData:{select:[],skip_suspended:!1},cron:{minute:"",hour:"",dayofmonth:"",month:"",dayofweek:""},ftp:{ftp_ip:"",ftp_username:"",ftp_password:"",ftp_path:"",ftp_port:"",ftp_secure:!1},append_to_path:"nothing",custom_append:"",encrypt:!1,password:""}),computed:{validWho(){return this.who==="all"||!!this.whoData.select.length},validWhen(){return this.when==="now"||!!this.cron.minute&&!!this.cron.hour&&!!this.cron.dayofmonth&&!!this.cron.month&&!!this.cron.dayofweek},validWhere(){return this.where==="local"||!!this.ftp.ftp_ip&&!!this.ftp.ftp_username&&!!this.ftp.ftp_password&&!!this.ftp.ftp_path&&!!this.ftp.ftp_port},...(0,p.Kc)(["client"])},created(){this.who=this.$api.cron.who.who,this.whoData.select=this.$api.cron.who.select,this.whoData.skip_suspended=this.$api.cron.who.skip_suspended,Object.assign(this.cron,this.$api.cron.when),this.where=this.$api.cron.where,Object.assign(this.ftp,this.$api.cron.settings),this.append_to_path=this.$api.cron.append.value,this.custom_append=this.$api.cron.custom_append||"",this.encrypt=!!this.$api.encryptionStatus.password,this.password=this.$api.encryptionStatus.password},methods:{submit(){(0,u.Q0)({id:this.id,who:this.who,select:this.whoData.select,skip_suspended:this.whoData.skip_suspended,when:"cron",...this.cron,where:this.where,...this.ftp,ftp_secure:this.ftp.ftp_secure?"ftps":"no",append_to_path:this.append_to_path,custom_append:this.custom_append,encryption_password:this.encrypt?this.password:""})}}},m=f,v=n("../node_modules/vue-style-loader/index.js!../node_modules/mini-css-extract-plugin/dist/loader.js??clonedRuleSet-13.use[1]!../node_modules/css-loader/dist/cjs.js??clonedRuleSet-13.use[2]!../node_modules/vue-loader/lib/loaders/stylePostLoader.js!../node_modules/postcss-loader/dist/cjs.js??clonedRuleSet-13.use[3]!../node_modules/sass-loader/dist/cjs.js??clonedRuleSet-13.use[4]!../node_modules/vue-loader/lib/index.js??vue-loader-options!../node_modules/unplugin/dist/webpack/loaders/transform.js?unpluginName=unplugin-vue-define-options!./js/pages/reseller/backups/modify.vue?vue&type=style&index=0&id=e4a8e124&prod&lang=scss&scoped=true&"),P=n("../node_modules/vue-loader/lib/runtime/componentNormalizer.js"),x=(0,P.Z)(m,t,i,!1,null,"e4a8e124",null),O=x.exports},"../node_modules/vue-style-loader/index.js!../node_modules/mini-css-extract-plugin/dist/loader.js??clonedRuleSet-13.use[1]!../node_modules/css-loader/dist/cjs.js??clonedRuleSet-13.use[2]!../node_modules/vue-loader/lib/loaders/stylePostLoader.js!../node_modules/postcss-loader/dist/cjs.js??clonedRuleSet-13.use[3]!../node_modules/sass-loader/dist/cjs.js??clonedRuleSet-13.use[4]!../node_modules/vue-loader/lib/index.js??vue-loader-options!../node_modules/unplugin/dist/webpack/loaders/transform.js?unpluginName=unplugin-vue-define-options!./js/pages/reseller/backups/modify.vue?vue&type=style&index=0&id=e4a8e124&prod&lang=scss&scoped=true&":function(h,d,n){var t=n("../node_modules/mini-css-extract-plugin/dist/loader.js??clonedRuleSet-13.use[1]!../node_modules/css-loader/dist/cjs.js??clonedRuleSet-13.use[2]!../node_modules/vue-loader/lib/loaders/stylePostLoader.js!../node_modules/postcss-loader/dist/cjs.js??clonedRuleSet-13.use[3]!../node_modules/sass-loader/dist/cjs.js??clonedRuleSet-13.use[4]!../node_modules/vue-loader/lib/index.js??vue-loader-options!../node_modules/unplugin/dist/webpack/loaders/transform.js?unpluginName=unplugin-vue-define-options!./js/pages/reseller/backups/modify.vue?vue&type=style&index=0&id=e4a8e124&prod&lang=scss&scoped=true&");t.__esModule&&(t=t.default),typeof t=="string"&&(t=[[h.id,t,""]]),t.locals&&(h.exports=t.locals);var i=n("../node_modules/vue-style-loader/lib/addStylesClient.js").Z,p=i("1941caa1",t,!0,{})},"./js/vue-globals/mixins sync recursive \\.js$":function(h,d,n){var t={"./bindApi.js":"./js/vue-globals/mixins/bindApi.js","./local/clickOutside.js":"./js/vue-globals/mixins/local/clickOutside.js","./local/inputValidation.js":"./js/vue-globals/mixins/local/inputValidation.js","./notification.js":"./js/vue-globals/mixins/notification.js","./reloadApiTable.js":"./js/vue-globals/mixins/reloadApiTable.js","./session.js":"./js/vue-globals/mixins/session.js","./staticData.js":"./js/vue-globals/mixins/staticData.js","vue-globals/mixins/bindApi.js":"./js/vue-globals/mixins/bindApi.js","vue-globals/mixins/local/clickOutside.js":"./js/vue-globals/mixins/local/clickOutside.js","vue-globals/mixins/local/inputValidation.js":"./js/vue-globals/mixins/local/inputValidation.js","vue-globals/mixins/notification.js":"./js/vue-globals/mixins/notification.js","vue-globals/mixins/reloadApiTable.js":"./js/vue-globals/mixins/reloadApiTable.js","vue-globals/mixins/session.js":"./js/vue-globals/mixins/session.js","vue-globals/mixins/staticData.js":"./js/vue-globals/mixins/staticData.js"};function i(l){var u=p(l);return n(u)}function p(l){if(!n.o(t,l)){var u=new Error("Cannot find module '"+l+"'");throw u.code="MODULE_NOT_FOUND",u}return t[l]}i.keys=function(){return Object.keys(t)},i.resolve=p,h.exports=i,i.id="./js/vue-globals/mixins sync recursive \\.js$"}}]);