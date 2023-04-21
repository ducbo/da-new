(self.webpackChunk=self.webpackChunk||[]).push([[9323],{"../node_modules/mini-css-extract-plugin/dist/loader.js??clonedRuleSet-13.use[1]!../node_modules/css-loader/dist/cjs.js??clonedRuleSet-13.use[2]!../node_modules/vue-loader/lib/loaders/stylePostLoader.js!../node_modules/postcss-loader/dist/cjs.js??clonedRuleSet-13.use[3]!../node_modules/sass-loader/dist/cjs.js??clonedRuleSet-13.use[4]!../node_modules/vue-loader/lib/index.js??vue-loader-options!../node_modules/unplugin/dist/webpack/loaders/transform.js?unpluginName=unplugin-vue-define-options!./js/pages/admin/backups/modify.vue?vue&type=style&index=0&id=58201d54&prod&lang=scss&scoped=true&":function(){},"./js/pages/admin/backups/modify.vue":function(i,u,a){"use strict";a.r(u),a.d(u,{default:function(){return v}});var s=function(){var e=this,t=e._self._c;return t("app-page",{attrs:{id:"modify-admin-backup"},scopedSlots:e._u([{key:"default",fn:function(){return[t("app-page-section",[t("ui-steps",{attrs:{steps:[{id:"who",label:e.$gettext("Step 1: Who"),desc:e.$gettext("Select users you would like to backup."),completed:e.validWho},{id:"when",label:e.$gettext("Step 2: When"),completed:e.validWhen,desc:e.$gettext("Select time period for backup.")},{id:"where",label:e.$gettext("Step 3: Where"),completed:e.validWhere,desc:e.$gettext("Select directory for backups.")},{id:"what",label:e.$gettext("Step 4: What"),completed:e.validWhat,desc:e.$gettext("Select data you would like to backup.")}],current:e.step,disabled:!e.$valid("modifyBackup")},on:{"update:current":function(n){e.step=n}},scopedSlots:e._u([{key:"step:who",fn:function(){return[t("div",[t("ui-form-element",{attrs:{"vertical-on-phone":!1,reverse:e.clientStore.isPhone},scopedSlots:e._u([{key:"title",fn:function(){return[t("span",{domProps:{textContent:e._s(e.$gettext("All Users"))}})]},proxy:!0},{key:"content",fn:function(){return[t("input-radio",{attrs:{value:"all"},model:{value:e.who,callback:function(n){e.who=n},expression:"who"}})]},proxy:!0}])}),e._v(" "),t("ui-form-element",{attrs:{"vertical-on-phone":!1,reverse:e.clientStore.isPhone},scopedSlots:e._u([{key:"title",fn:function(){return[t("span",{domProps:{textContent:e._s(e.$gettext("All Users Except Selected"))}})]},proxy:!0},{key:"content",fn:function(){return[t("input-radio",{attrs:{value:"except"},model:{value:e.who,callback:function(n){e.who=n},expression:"who"}})]},proxy:!0}])}),e._v(" "),t("ui-form-element",{attrs:{"vertical-on-phone":!1,reverse:e.clientStore.isPhone},scopedSlots:e._u([{key:"title",fn:function(){return[t("span",{domProps:{textContent:e._s(e.$gettext("Selected Users"))}})]},proxy:!0},{key:"content",fn:function(){return[t("input-radio",{attrs:{value:"selected"},model:{value:e.who,callback:function(n){e.who=n},expression:"who"}})]},proxy:!0}])}),e._v(" "),t("ui-form-element",{attrs:{"vertical-on-phone":!1,reverse:e.clientStore.isPhone},scopedSlots:e._u([{key:"title",fn:function(){return[t("span",{domProps:{textContent:e._s(e.$gettext("Selected Creators and their users"))}})]},proxy:!0},{key:"content",fn:function(){return[t("input-radio",{attrs:{value:"creator_all"},model:{value:e.who,callback:function(n){e.who=n},expression:"who"}})]},proxy:!0}])}),e._v(" "),e.who!=="all"?[t("ui-form-element",{scopedSlots:e._u([{key:"title",fn:function(){return[t("span",{domProps:{textContent:e._s(e.$gettext("Users"))}})]},proxy:!0},{key:"content",fn:function(){return[t("input-select-multiple",{staticClass:"width:100%",attrs:{options:e.userGroups},model:{value:e.whoData.select,callback:function(n){e.$set(e.whoData,"select",n)},expression:"whoData.select"}})]},proxy:!0}],null,!1,447379716)})]:e._e(),e._v(" "),t("ui-form-element",{attrs:{underline:!1,"vertical-on-phone":!1,reverse:e.clientStore.isPhone},scopedSlots:e._u([{key:"title",fn:function(){return[t("span",{domProps:{textContent:e._s(e.$gettext("Skip Suspended"))}})]},proxy:!0},{key:"content",fn:function(){return[t("input-checkbox",{model:{value:e.whoData.skip_suspended,callback:function(n){e.$set(e.whoData,"skip_suspended",n)},expression:"whoData.skip_suspended"}})]},proxy:!0}])})],2)]},proxy:!0},{key:"step:when",fn:function(){return[t("div",[t("ui-form-element",{attrs:{group:"modifyBackupWhen",validators:{required:!0}},scopedSlots:e._u([{key:"title",fn:function(){return[t("span",{domProps:{textContent:e._s(e.$gettext("Minute"))}})]},proxy:!0},{key:"tooltip",fn:function(){return[t("span",[e._v("0\u201359")])]},proxy:!0},{key:"content",fn:function(){return[t("input-text",{model:{value:e.whenData.minute,callback:function(n){e.$set(e.whenData,"minute",n)},expression:"whenData.minute"}})]},proxy:!0}])}),e._v(" "),t("ui-form-element",{attrs:{group:"modifyBackupWhen",validators:{required:!0}},scopedSlots:e._u([{key:"title",fn:function(){return[t("span",{domProps:{textContent:e._s(e.$gettext("Hour"))}})]},proxy:!0},{key:"tooltip",fn:function(){return[t("span",[e._v("0\u201323")])]},proxy:!0},{key:"content",fn:function(){return[t("input-text",{model:{value:e.whenData.hour,callback:function(n){e.$set(e.whenData,"hour",n)},expression:"whenData.hour"}})]},proxy:!0}])}),e._v(" "),t("ui-form-element",{attrs:{group:"modifyBackupWhen",validators:{required:!0}},scopedSlots:e._u([{key:"title",fn:function(){return[t("span",{domProps:{textContent:e._s(e.$gettext("Day of Month"))}})]},proxy:!0},{key:"tooltip",fn:function(){return[t("span",[e._v("1\u201331")])]},proxy:!0},{key:"content",fn:function(){return[t("input-text",{model:{value:e.whenData.dayofmonth,callback:function(n){e.$set(e.whenData,"dayofmonth",n)},expression:"whenData.dayofmonth"}})]},proxy:!0}])}),e._v(" "),t("ui-form-element",{attrs:{group:"modifyBackupWhen",validators:{required:!0}},scopedSlots:e._u([{key:"title",fn:function(){return[t("span",{domProps:{textContent:e._s(e.$gettext("Month"))}})]},proxy:!0},{key:"tooltip",fn:function(){return[t("span",[e._v("1\u201312")])]},proxy:!0},{key:"content",fn:function(){return[t("input-text",{model:{value:e.whenData.month,callback:function(n){e.$set(e.whenData,"month",n)},expression:"whenData.month"}})]},proxy:!0}])}),e._v(" "),t("ui-form-element",{attrs:{group:"modifyBackupWhen",validators:{required:!0},underline:!1},scopedSlots:e._u([{key:"title",fn:function(){return[t("span",{domProps:{textContent:e._s(e.$gettext("Day of Week"))}})]},proxy:!0},{key:"tooltip",fn:function(){return[t("span",{domProps:{textContent:e._s(e.$gettext("0\u20137; 0, 7 = Sunday"))}})]},proxy:!0},{key:"content",fn:function(){return[t("input-text",{model:{value:e.whenData.dayofweek,callback:function(n){e.$set(e.whenData,"dayofweek",n)},expression:"whenData.dayofweek"}})]},proxy:!0}])})],1)]},proxy:!0},{key:"step:where",fn:function(){return[t("div",[t("ui-form-element",{attrs:{"vertical-on-phone":!1,reverse:e.clientStore.isPhone},scopedSlots:e._u([{key:"title",fn:function(){return[t("span",{domProps:{textContent:e._s(e.$gettext("Local"))}})]},proxy:!0},{key:"content",fn:function(){return[t("input-radio",{attrs:{value:"local"},model:{value:e.where,callback:function(n){e.where=n},expression:"where"}})]},proxy:!0}])}),e._v(" "),t("transition",{attrs:{name:"fade"}},[t("ui-form-element",{attrs:{group:"modifyBackupWhere",validators:{required:!0}},scopedSlots:e._u([{key:"title",fn:function(){return[t("span",{domProps:{textContent:e._s(e.$gettext("Path"))}})]},proxy:!0},{key:"content",fn:function(){return[t("input-text",{model:{value:e.whereData.local_path,callback:function(n){e.$set(e.whereData,"local_path",n)},expression:"whereData.local_path"}})]},proxy:!0}])})],1),e._v(" "),t("ui-form-element",{attrs:{"vertical-on-phone":!1,reverse:e.clientStore.isPhone},scopedSlots:e._u([{key:"title",fn:function(){return[t("span",{domProps:{textContent:e._s(e.$gettext("FTP"))}})]},proxy:!0},{key:"content",fn:function(){return[t("input-radio",{attrs:{value:"ftp"},model:{value:e.where,callback:function(n){e.where=n},expression:"where"}})]},proxy:!0}])}),e._v(" "),e.where==="ftp"?t("ui-form-element",{scopedSlots:e._u([{key:"title",fn:function(){return[t("span",{domProps:{textContent:e._s(e.$gettext("FTP Settings"))}})]},proxy:!0},{key:"content",fn:function(){return[t("div",[t("ui-form-element",{attrs:{validators:{required:!0},group:"modifyBackupWhere"},scopedSlots:e._u([{key:"title",fn:function(){return[t("span",{domProps:{textContent:e._s(e.$gettext("IP"))}})]},proxy:!0},{key:"content",fn:function(){return[t("input-text",{model:{value:e.whereData.ftp_ip,callback:function(n){e.$set(e.whereData,"ftp_ip",n)},expression:"whereData.ftp_ip"}})]},proxy:!0}],null,!1,863485065)}),e._v(" "),t("ui-form-element",{attrs:{validators:{required:!0},group:"modifyBackupWhere"},scopedSlots:e._u([{key:"title",fn:function(){return[t("span",{domProps:{textContent:e._s(e.$gettext("Username"))}})]},proxy:!0},{key:"content",fn:function(){return[t("input-text",{model:{value:e.whereData.ftp_username,callback:function(n){e.$set(e.whereData,"ftp_username",n)},expression:`
                                                    whereData.ftp_username
                                                `}})]},proxy:!0}],null,!1,2783742249)}),e._v(" "),t("ui-form-element",{attrs:{validators:{required:!0},group:"modifyBackupWhere"},scopedSlots:e._u([{key:"title",fn:function(){return[t("span",{domProps:{textContent:e._s(e.$gettext("Password"))}})]},proxy:!0},{key:"content",fn:function(){return[t("input-text",{model:{value:e.whereData.ftp_password,callback:function(n){e.$set(e.whereData,"ftp_password",n)},expression:`
                                                    whereData.ftp_password
                                                `}})]},proxy:!0}],null,!1,2750199593)}),e._v(" "),t("ui-form-element",{attrs:{validators:{required:!0},group:"modifyBackupWhere"},scopedSlots:e._u([{key:"title",fn:function(){return[t("span",{domProps:{textContent:e._s(e.$gettext("Remote Path"))}})]},proxy:!0},{key:"content",fn:function(){return[t("input-text",{model:{value:e.whereData.ftp_path,callback:function(n){e.$set(e.whereData,"ftp_path",n)},expression:"whereData.ftp_path"}})]},proxy:!0}],null,!1,2606954541)}),e._v(" "),t("ui-form-element",{attrs:{validators:{required:!0},group:"modifyBackupWhere"},scopedSlots:e._u([{key:"title",fn:function(){return[t("span",{domProps:{textContent:e._s(e.$gettext("Port"))}})]},proxy:!0},{key:"content",fn:function(){return[t("input-text",{attrs:{number:""},model:{value:e.whereData.ftp_port,callback:function(n){e.$set(e.whereData,"ftp_port",n)},expression:"whereData.ftp_port"}})]},proxy:!0}],null,!1,1606006144)}),e._v(" "),t("ui-form-element",{scopedSlots:e._u([{key:"title",fn:function(){return[t("span",{domProps:{textContent:e._s(e.$gettext("Secure FTP"))}})]},proxy:!0},{key:"content",fn:function(){return[t("input-checkbox",{model:{value:e.whereData.ftp_secure,callback:function(n){e.$set(e.whereData,"ftp_secure",n)},expression:`
                                                    whereData.ftp_secure
                                                `}})]},proxy:!0}],null,!1,3274344965)})],1)]},proxy:!0}],null,!1,557964541)}):e._e(),e._v(" "),t("ui-form-element",{attrs:{underline:e.whereData.append_to_path==="custom"||e.encryptionEnabled},scopedSlots:e._u([{key:"title",fn:function(){return[t("span",{domProps:{textContent:e._s(e.$gettext("Append"))}})]},proxy:!0},{key:"content",fn:function(){return[t("div",{directives:[{name:"flex",rawName:"v-flex"}]},[t("input-select",{attrs:{options:e.options.appendOptions},model:{value:e.whereData.append_to_path,callback:function(n){e.$set(e.whereData,"append_to_path",n)},expression:"whereData.append_to_path"}})],1)]},proxy:!0}])}),e._v(" "),e.whereData.append_to_path==="custom"?t("ui-form-element",{attrs:{"path-segment":"directadmin/backup-restore-migration/backups.html#custom-append-values-in-backup-path",underline:e.encryptionEnabled},scopedSlots:e._u([{key:"title",fn:function(){return[t("span",{domProps:{textContent:e._s(e.$gettext("Custom Path"))}})]},proxy:!0},{key:"content",fn:function(){return[t("input-text",{directives:[{name:"margin",rawName:"v-margin",value:[1,0],expression:"[1, 0]"}],attrs:{prefix:"/"},model:{value:e.whereData.custom_append,callback:function(n){e.$set(e.whereData,"custom_append",n)},expression:"whereData.custom_append"}})]},proxy:!0}],null,!1,3712528804)}):e._e(),e._v(" "),e.encryptionEnabled?[t("ui-form-element",{attrs:{underline:e.encrypt,"vertical-on-phone":!1,reverse:e.clientStore.isPhone},scopedSlots:e._u([{key:"title",fn:function(){return[t("span",{domProps:{textContent:e._s(e.$gettext("Backup Encryption"))}})]},proxy:!0},{key:"content",fn:function(){return[t("input-checkbox",{model:{value:e.encrypt,callback:function(n){e.encrypt=n},expression:"encrypt"}})]},proxy:!0}],null,!1,769703515)}),e._v(" "),t("transition",{attrs:{name:"fadeBounce"}},[e.encrypt?t("ui-form-element",{attrs:{underline:!1},scopedSlots:e._u([{key:"title",fn:function(){return[t("span",{domProps:{textContent:e._s(e.$gettext("Password"))}})]},proxy:!0},{key:"content",fn:function(){return[t("input-password",{model:{value:e.password,callback:function(n){e.password=n},expression:"password"}})]},proxy:!0}],null,!1,3464064881)}):e._e()],1)]:e._e()],2)]},proxy:!0},{key:"step:what",fn:function(){return[t("div",[t("ui-form-element",{attrs:{reverse:e.clientStore.isPhone,"vertical-on-phone":!1},scopedSlots:e._u([{key:"title",fn:function(){return[t("span",{domProps:{textContent:e._s(e.$gettext("All Data"))}})]},proxy:!0},{key:"content",fn:function(){return[t("input-radio",{attrs:{value:"all"},model:{value:e.what,callback:function(n){e.what=n},expression:"what"}})]},proxy:!0}])}),e._v(" "),t("ui-form-element",{attrs:{underline:!1,reverse:e.clientStore.isPhone,"vertical-on-phone":!1},scopedSlots:e._u([{key:"title",fn:function(){return[t("span",{domProps:{textContent:e._s(e.$gettext("Selected Data"))}})]},proxy:!0},{key:"content",fn:function(){return[t("input-radio",{attrs:{value:"select"},model:{value:e.what,callback:function(n){e.what=n},expression:"what"}})]},proxy:!0}])}),e._v(" "),e.what==="select"&&!e.clientStore.isPhone?t("ui-form-element",{scopedSlots:e._u([{key:"title",fn:function(){return[t("span",[e._v("\xA0")])]},proxy:!0},{key:"content",fn:function(){return[t("div",{staticClass:"checkboxes-list"},[t("input-checkbox",{attrs:{value:"domain"},model:{value:e.whatData.option,callback:function(n){e.$set(e.whatData,"option",n)},expression:"whatData.option"}},[t("span",{domProps:{textContent:e._s(e.$gettext("Domains Directory"))}})]),e._v(" "),t("input-checkbox",{attrs:{value:"subdomain"},model:{value:e.whatData.option,callback:function(n){e.$set(e.whatData,"option",n)},expression:"whatData.option"}},[t("span",{domProps:{textContent:e._s(e.$gettext("Subdomain Lists"))}})]),e._v(" "),t("input-checkbox",{attrs:{value:"ftp"},model:{value:e.whatData.option,callback:function(n){e.$set(e.whatData,"option",n)},expression:"whatData.option"}},[t("span",{domProps:{textContent:e._s(e.$gettext("FTP Accounts"))}})]),e._v(" "),t("input-checkbox",{attrs:{value:"ftpsettings"},model:{value:e.whatData.option,callback:function(n){e.$set(e.whatData,"option",n)},expression:"whatData.option"}},[t("span",{domProps:{textContent:e._s(e.$gettext("FTP Settings"))}})]),e._v(" "),t("input-checkbox",{attrs:{value:"database"},model:{value:e.whatData.option,callback:function(n){e.$set(e.whatData,"option",n)},expression:"whatData.option"}},[t("span",{domProps:{textContent:e._s(e.$gettext("Database Settings"))}})]),e._v(" "),t("input-checkbox",{attrs:{value:"database_data"},model:{value:e.whatData.option,callback:function(n){e.$set(e.whatData,"option",n)},expression:"whatData.option"}},[t("span",{domProps:{textContent:e._s(e.$gettext("Database Data"))}})]),e._v(" "),t("input-checkbox",{attrs:{value:"forwarder"},model:{value:e.whatData.option,callback:function(n){e.$set(e.whatData,"option",n)},expression:"whatData.option"}},[t("span",{domProps:{textContent:e._s(e.$gettext("Forwarders"))}})]),e._v(" "),t("input-checkbox",{attrs:{value:"email"},model:{value:e.whatData.option,callback:function(n){e.$set(e.whatData,"option",n)},expression:"whatData.option"}},[t("span",{domProps:{textContent:e._s(e.$gettext("E-mail Accounts"))}})]),e._v(" "),t("input-checkbox",{attrs:{value:"email_data"},model:{value:e.whatData.option,callback:function(n){e.$set(e.whatData,"option",n)},expression:"whatData.option"}},[t("span",{domProps:{textContent:e._s(e.$gettext("E-mail Data"))}})]),e._v(" "),t("input-checkbox",{attrs:{value:"emailsettings"},model:{value:e.whatData.option,callback:function(n){e.$set(e.whatData,"option",n)},expression:"whatData.option"}},[t("span",{domProps:{textContent:e._s(e.$gettext("E-mail Settings"))}})]),e._v(" "),t("input-checkbox",{attrs:{value:"vacation"},model:{value:e.whatData.option,callback:function(n){e.$set(e.whatData,"option",n)},expression:"whatData.option"}},[t("span",{domProps:{textContent:e._s(e.$gettext("Vacation Messages"))}})]),e._v(" "),t("input-checkbox",{attrs:{value:"autoresponder"},model:{value:e.whatData.option,callback:function(n){e.$set(e.whatData,"option",n)},expression:"whatData.option"}},[t("span",{domProps:{textContent:e._s(e.$gettext("Autoresponders"))}})]),e._v(" "),t("input-checkbox",{attrs:{value:"list"},model:{value:e.whatData.option,callback:function(n){e.$set(e.whatData,"option",n)},expression:"whatData.option"}},[t("span",{domProps:{textContent:e._s(e.$gettext("Mailing Lists"))}})]),e._v(" "),t("input-checkbox",{attrs:{value:"trash"},model:{value:e.whatData.option,callback:function(n){e.$set(e.whatData,"option",n)},expression:"whatData.option"}},[t("span",{domProps:{textContent:e._s(e.$gettext("Deleted Trash Data"))}})]),e._v(" "),t("div",{staticClass:"select-links"},[t("ui-link",{on:{click:e.selectAllDataItems}},[t("span",{domProps:{textContent:e._s(e.$gettext("All"))}})]),e._v(`
                                        /
                                        `),t("ui-link",{on:{click:function(n){e.whatData.option=[]}}},[t("span",{domProps:{textContent:e._s(e.$gettext("None"))}})])],1)],1)]},proxy:!0}],null,!1,752440753)}):e._e()],1)]},proxy:!0},{key:"buttons",fn:function(){return[t("ui-button",{attrs:{theme:"primary",disabled:!(e.validWho&&e.validWhere&&e.validWhat&&e.validWhen)},on:{click:e.updateBackup}},[t("span",{domProps:{textContent:e._s(e.$gettext("Save"))}})])]},proxy:!0}])})],1)]},proxy:!0}])})},l=[],p=a("./js/stores/index.ts"),c=a("../node_modules/ramda/es/index.js"),r=a("./js/api/commands/admin/backups/index.js"),h=a("./js/vue-globals/mixins.js"),f=a("./js/modules/utils/index.js"),m={preload:[r.jF,r.v6],mixins:[(0,h.$bindTab)({defaultTab:"who",param:"step"})],props:{id:{type:String,required:!0}},data(){return{who:"selected",whoData:{select:[],skip_suspended:!1},when:"cron",whenData:{minute:"",hour:"",dayofmonth:"",month:"",dayofweek:""},where:"local",whereData:{local_path:"",ftp_ip:"",ftp_username:"",ftp_password:"",ftp_path:"",ftp_port:"",ftp_secure:!1,append_to_path:"custom",custom_append:""},what:"all",whatData:{option:[]},creatorSelect:"",checkedUsers:[],encrypt:!1,password:""}},api:[{command:r.jF,bind:"details"},{command:r.v6,bind:"encryption"}],computed:{validWho(){return this.who==="all"||!!this.whoData.select.length},validWhen(){return Object.values(this.whenData).every(o=>!!o)},validWhere(){return this.where==="local"&&!!this.whereData.local_path||this.where==="ftp"&&!!this.whereData.ftp_ip&&!!this.whereData.ftp_username&&!!this.whereData.ftp_password&&!!this.whereData.ftp_path&&!!this.whereData.ftp_port},validWhat(){return this.what==="all"||!!this.whatData.option.length},options(){return this.$api.details},encryptionEnabled(){return this.$api.encryption.enabled},requestData(){return{id:this.id,who:this.who,when:this.when,where:this.where,what:this.what,skip_suspended:this.whoData.skip_suspended,select:this.whoData.select,...this.whenData,...this.whereData,ftp_secure:this.whereData.ftp_secure?"ftps":"no",...this.whatData,encryption_password:this.password}},creators(){return Object.keys(this.options.whoData.users)},users(){const o=n=>({user:n,type:this.options.usertypes[n]}),e=this.creators.map(o),t=(n,d)=>[...n,d,...this.options.whoData.users[d.user].map(o)];return e.reduce(t,[])},userGroups(){return c.IDH((o,e)=>({label:this.$gettextInterpolate(this.$gettext("Reseller: %{ creator }"),{creator:e}),entries:[e,...o]}),this.options.whoData.users)},...(0,p.Kc)(["client"])},mounted(){this.options.whoData.select.forEach(this.selectUser),this.whoData.skip_suspended=this.options.whoData.skip_suspended},created(){this.creatorSelect=this.creators[0],this.who=this.options.who,this.what=this.options.what,this.where=this.options.where,this.whatData.option=f._.cloneDeep(this.options.whatData.select||[]),Object.assign(this.whereData,this.options.whereData),Object.assign(this.whenData,this.options.whenData),this.whereData.custom_append=this.whereData.custom_append||"",this.encrypt=!!this.$api.encryption.password,this.password=this.$api.encryption.password,this.$watch("whatData.option",(o,e)=>{o.includes("database_data")&&!e.includes("database_data")&&!o.includes("database")&&(e.includes("database")?this.whatData.option=this.whatData.option.filter(t=>t!=="database_data"):this.whatData.option.push("database")),o.includes("database")&&!e.includes("database")&&!o.includes("database_data")&&(e.includes("database_data")||this.whatData.option.push("database_data")),o.includes("email_data")&&!e.includes("database_data")&&!o.includes("email")&&(e.includes("email")?this.whatData.option=this.whatData.option.filter(t=>t!=="email_data"):this.whatData.option.push("email")),o.includes("email")&&!e.includes("email")&&!o.includes("email_data")&&(e.includes("email_data")||this.whatData.option.push("email_data"))})},methods:{selectAllDataItems(){this.whatData.option=["domain","subdomain","ftp","ftpsettings","database","database_data","forwarder","email","email_data","emailsettings","vacation","autoresponder","list","trash"]},selectUser(o){const e=t=>o===t.user;if(!this.whoData.select.find(e)){const{user:t}=this.users.find(e)||{};o&&this.whoData.select.push(t)}},selectCreator(){[this.creatorSelect,...this.options.whoData.users[this.creatorSelect]].forEach(this.selectUser)},async updateBackup(){await(0,r.Oo)(this.requestData)&&this.$router.push({name:"admin/backups"})}}},x=m,y=a("../node_modules/vue-style-loader/index.js!../node_modules/mini-css-extract-plugin/dist/loader.js??clonedRuleSet-13.use[1]!../node_modules/css-loader/dist/cjs.js??clonedRuleSet-13.use[2]!../node_modules/vue-loader/lib/loaders/stylePostLoader.js!../node_modules/postcss-loader/dist/cjs.js??clonedRuleSet-13.use[3]!../node_modules/sass-loader/dist/cjs.js??clonedRuleSet-13.use[4]!../node_modules/vue-loader/lib/index.js??vue-loader-options!../node_modules/unplugin/dist/webpack/loaders/transform.js?unpluginName=unplugin-vue-define-options!./js/pages/admin/backups/modify.vue?vue&type=style&index=0&id=58201d54&prod&lang=scss&scoped=true&"),w=a("../node_modules/vue-loader/lib/runtime/componentNormalizer.js"),_=(0,w.Z)(x,s,l,!1,null,"58201d54",null),v=_.exports},"../node_modules/vue-style-loader/index.js!../node_modules/mini-css-extract-plugin/dist/loader.js??clonedRuleSet-13.use[1]!../node_modules/css-loader/dist/cjs.js??clonedRuleSet-13.use[2]!../node_modules/vue-loader/lib/loaders/stylePostLoader.js!../node_modules/postcss-loader/dist/cjs.js??clonedRuleSet-13.use[3]!../node_modules/sass-loader/dist/cjs.js??clonedRuleSet-13.use[4]!../node_modules/vue-loader/lib/index.js??vue-loader-options!../node_modules/unplugin/dist/webpack/loaders/transform.js?unpluginName=unplugin-vue-define-options!./js/pages/admin/backups/modify.vue?vue&type=style&index=0&id=58201d54&prod&lang=scss&scoped=true&":function(i,u,a){var s=a("../node_modules/mini-css-extract-plugin/dist/loader.js??clonedRuleSet-13.use[1]!../node_modules/css-loader/dist/cjs.js??clonedRuleSet-13.use[2]!../node_modules/vue-loader/lib/loaders/stylePostLoader.js!../node_modules/postcss-loader/dist/cjs.js??clonedRuleSet-13.use[3]!../node_modules/sass-loader/dist/cjs.js??clonedRuleSet-13.use[4]!../node_modules/vue-loader/lib/index.js??vue-loader-options!../node_modules/unplugin/dist/webpack/loaders/transform.js?unpluginName=unplugin-vue-define-options!./js/pages/admin/backups/modify.vue?vue&type=style&index=0&id=58201d54&prod&lang=scss&scoped=true&");s.__esModule&&(s=s.default),typeof s=="string"&&(s=[[i.id,s,""]]),s.locals&&(i.exports=s.locals);var l=a("../node_modules/vue-style-loader/lib/addStylesClient.js").Z,p=l("3fa1538a",s,!0,{})}}]);