"use strict";(self.webpackChunk=self.webpackChunk||[]).push([[9761],{"./js/api/commands/user/cronjobs.ts":function(h,c,o){o.d(c,{Jh:function(){return i},SX:function(){return m},cX:function(){return x},it:function(){return v},vP:function(){return f},yl:function(){return l},zk:function(){return d}});var n=o("./js/api/command/index.js"),a=o("../node_modules/ramda/es/index.js");const r="/CMD_CRON_JOBS",d=n.Z.get({url:r,id:"CRON_JOBS",params:{ipp:"99999",page:"1"},mapResponse:{email:a.vgT("MAILTO"),rows:a.zGw(a.vgT("crons"),a.CEd(["info"]),a.VO0)}}),l=n.Z.select({url:r,params:{action:"delete",delete:!0}}),i=n.Z.post({url:r,params:{action:"create"},schema:{reboot:n.Z.REQUIRED_BOOL,minute:n.Z.REQUIRED_STRING,hour:n.Z.REQUIRED_STRING,dayofmonth:n.Z.REQUIRED_STRING,month:n.Z.REQUIRED_STRING,dayofweek:n.Z.REQUIRED_STRING}}),u=n.Z.post({url:r,params:{save:!0},schema:{id:n.Z.REQUIRED_STRING,command:n.Z.REQUIRED_STRING}}),m=u.extend({url:r,params:{reboot:!0}}),f=u.extend({url:r,schema:{minute:n.Z.REQUIRED_STRING,hour:n.Z.REQUIRED_STRING,dayofmonth:n.Z.REQUIRED_STRING,month:n.Z.REQUIRED_STRING,dayofweek:n.Z.REQUIRED_STRING}}),v=n.Z.post({url:r,params:{action:"saveemail"},schema:{email:n.Z.REQUIRED_STRING}}),x=n.Z.get({url:r,id:"CRON_PHP_BIN_PATH",response:!1,mapResponse:_=>_.set_php_bin_path_in_crons==="1"})},"./js/composables/dateFilter.ts":function(h,c,o){o.d(c,{W:function(){return l},f:function(){return r.f}});var n=o("../node_modules/ramda/es/index.js"),a=o("../node_modules/date-fns/esm/format/index.js"),r=o("./js/modules/date-formats.ts"),d=o("./js/modules/customizations/date-formats/default.ts");const l=n.WAo((i,u)=>{if(u)try{return(0,a.Z)(u,r.f.value[i])}catch(m){return console.warn(`Given ${i} format is incorrect:
${m.message}`),(0,a.Z)(u,d.d[i])}return""})},"./js/pages/user/cronjobs/create.vue":function(h,c,o){o.r(c),o.d(c,{default:function(){return g}});var n=function(){var t=this,e=t._self._c;return e("app-page",{scopedSlots:t._u([{key:"details:shared",fn:function(){return[e("ui-infobar-item",{attrs:{title:t.$gettext("Details")}},[e("ul",[e("li",[e("span",{domProps:{textContent:t._s(t.$gettext("Valid Cron time values are the numbers indicated and *."))}})]),t._v(" "),e("li",[e("span",{domProps:{textContent:t._s(t.$gettext("You can specify exact times using commas to separate them. e.g. 1,2,3 (minutes 1,2 and 3)"))}})]),t._v(" "),e("li",[e("span",{domProps:{textContent:t._s(t.$gettext("You can specify spans using a dash. e.g. 5-7 (minutes 5 to 7)"))}})]),t._v(" "),e("li",[e("span",{domProps:{textContent:t._s(t.$gettext("You can specify intervals using a star and a forward slash. e.g. */2 (every 2nd minute)"))}})]),t._v(" "),e("li",[e("span",{domProps:{textContent:t._s(t.$gettext("You can combine them to create a more precise schedule. e.g. 1,5,11-15,30-59/2 (minutes 1, 5, 11 to 15 and every 2nd minute between 30 and 59)"))}})])]),t._v(" "),e("ui-pre",{attrs:{"text-wrap":!1,"option-checkboxes":!1,"content-lines":[`${t.$api.phpBinPath?"":"/usr/local/bin/"}php /home/admin/domains/domain.com/public_html/script.php`,"/usr/local/bin/curl --silent http://www.domain.com/cron.php > /dev/null","/usr/bin/wget -O /dev/null http://www.domain.com/cron.php"]},scopedSlots:t._u([{key:"header",fn:function(){return[e("span",{staticClass:"txt:bold",domProps:{textContent:t._s(t.$gettext("Sample Cron commands:"))}})]},proxy:!0}])})],1)]},proxy:!0},{key:"default",fn:function(){return[e("app-page-section",[e("ui-form-element",{scopedSlots:t._u([{key:"title",fn:function(){},proxy:!0},{key:"content",fn:function(){return[e("input-checkbox",{attrs:{label:t.$gettext("Run on @reboot")},model:{value:t.reboot,callback:function(s){t.reboot=s},expression:"reboot"}})]},proxy:!0}])})],1),t._v(" "),t.reboot?t._e():e("app-page-section",[e("ui-form-element",{scopedSlots:t._u([{key:"title",fn:function(){return[e("span",{domProps:{textContent:t._s(t.$gettext("Current Time"))}})]},proxy:!0},{key:"content",fn:function(){return[e("input-text",{attrs:{disabled:"disabled",value:t.currentTime}})]},proxy:!0}],null,!1,217228488)}),t._v(" "),e("ui-form-element",{attrs:{group:"createCronJob",validators:{required:!0}},scopedSlots:t._u([{key:"title",fn:function(){return[e("span",{domProps:{textContent:t._s(t.$gettext("Minute"))}})]},proxy:!0},{key:"tooltip",fn:function(){return[e("span",[t._v("0\u201359")])]},proxy:!0},{key:"content",fn:function(){return[e("input-text",{model:{value:t.minute,callback:function(s){t.minute=s},expression:"minute"}})]},proxy:!0}],null,!1,2190455782)}),t._v(" "),e("ui-form-element",{attrs:{group:"createCronJob",validators:{required:!0}},scopedSlots:t._u([{key:"title",fn:function(){return[e("span",{domProps:{textContent:t._s(t.$gettext("Hour"))}})]},proxy:!0},{key:"tooltip",fn:function(){return[e("span",[t._v("0\u201323")])]},proxy:!0},{key:"content",fn:function(){return[e("input-text",{model:{value:t.hour,callback:function(s){t.hour=s},expression:"hour"}})]},proxy:!0}],null,!1,4003366187)}),t._v(" "),e("ui-form-element",{attrs:{group:"createCronJob",validators:{required:!0}},scopedSlots:t._u([{key:"title",fn:function(){return[e("span",{domProps:{textContent:t._s(t.$gettext("Day of Month"))}})]},proxy:!0},{key:"tooltip",fn:function(){return[e("span",[t._v("1\u201331")])]},proxy:!0},{key:"content",fn:function(){return[e("input-text",{model:{value:t.dayOfMonth,callback:function(s){t.dayOfMonth=s},expression:"dayOfMonth"}})]},proxy:!0}],null,!1,533752041)}),t._v(" "),e("ui-form-element",{attrs:{group:"createCronJob",validators:{required:!0}},scopedSlots:t._u([{key:"title",fn:function(){return[e("span",{domProps:{textContent:t._s(t.$gettext("Month"))}})]},proxy:!0},{key:"tooltip",fn:function(){return[e("span",[t._v("1\u201312")])]},proxy:!0},{key:"content",fn:function(){return[e("input-text",{model:{value:t.month,callback:function(s){t.month=s},expression:"month"}})]},proxy:!0}],null,!1,3938906568)}),t._v(" "),e("ui-form-element",{scopedSlots:t._u([{key:"title",fn:function(){return[t._v(`
                    >
                    `),e("span",{domProps:{textContent:t._s(t.$gettext("Day of Week"))}})]},proxy:!0},{key:"tooltip",fn:function(){return[e("span",{domProps:{textContent:t._s(t.$gettext("0-7; 0, 7 = Sunday"))}})]},proxy:!0},{key:"content",fn:function(){return[e("input-text",{model:{value:t.dayOfWeek,callback:function(s){t.dayOfWeek=s},expression:"dayOfWeek"}})]},proxy:!0}],null,!1,3977749617)})],1),t._v(" "),e("app-page-section",[e("ui-form-element",{attrs:{group:"createCronJob",validators:{required:!0}},scopedSlots:t._u([{key:"title",fn:function(){return[e("span",{domProps:{textContent:t._s(t.$gettext("Command"))}})]},proxy:!0},{key:"tooltip",fn:function(){return[e("span",[t._v(`
                        `+t._s(t.$gettext("To access a specific URL periodically use a command like:"))+`
                        `),e("br"),t._v(`
                        curl -L -s https://example.com/cron.php
                    `)])]},proxy:!0},{key:"content",fn:function(){return[e("div",{directives:[{name:"flex",rawName:"v-flex",value:{dir:"column"},expression:"{ dir: 'column' }"}]},[e("input-textarea",{model:{value:t.command,callback:function(s){t.command=s},expression:"command"}})],1)]},proxy:!0}])})],1)]},proxy:!0},{key:"footer:buttons",fn:function(){return[e("ui-button",{key:"preventButton",attrs:{disabled:t.emailPrevented,theme:"safe",size:"big"},on:{click:t.preventEmail}},[e("span",{domProps:{textContent:t._s(t.$gettext("Prevent E-mail"))}})]),t._v(" "),e("ui-button",{directives:[{name:"margin",rawName:"v-margin:left",value:1,expression:"1",arg:"left"}],attrs:{theme:"safe","validate-group":"createCronJob"},on:{click:t.createCronJob}},[e("span",{domProps:{textContent:t._s(t.$gettext("Create"))}})])]},proxy:!0}])})},a=[],r=o("./js/api/commands/user/cronjobs.ts"),d=o("./js/openapi/login.ts"),l=o("../node_modules/vue/dist/vue.common.prod.js"),i=o("./js/composables/dateFilter.ts"),u=o("../node_modules/date-fns/esm/addMilliseconds/index.js");const m=async()=>{const p=await(0,d.Nr)();if(p.error)return p.error.type;let t=performance.now();const e=(0,l.ref)(new Date(p.data.time));return setInterval(()=>{const y=performance.now(),R=Math.round(y-t);t=y,e.value=(0,u.Z)(e.value,R)},1e3,[performance.now()]),(0,l.computed)(()=>(0,i.W)("datetime",e.value))};var f={preload:r.cX,api:[{command:r.cX,bind:"phpBinPath"}],data(){return{minute:"*",hour:"*",dayOfMonth:"*",month:"*",dayOfWeek:"*",command:"",reboot:!1,currentTime:this.$gettext("loading server data...")}},computed:{emailPrevented(){return this.command.includes(" >/dev/null 2>&1")}},async created(){this.command=this.$_session.homeDir,this.currentTime=await m()},methods:{async createCronJob(){await(0,r.Jh)({reboot:this.reboot,minute:this.minute,hour:this.hour,dayofmonth:this.dayOfMonth,month:this.month,dayofweek:this.dayOfWeek,command:this.command})&&this.$router.back()},preventEmail(){this.command=`${this.command} >/dev/null 2>&1`}}},v=f,x=o("../node_modules/vue-loader/lib/runtime/componentNormalizer.js"),_=(0,x.Z)(v,n,a,!1,null,null,null),g=_.exports}}]);