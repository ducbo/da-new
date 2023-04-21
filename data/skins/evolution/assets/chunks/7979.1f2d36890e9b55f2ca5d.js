(self.webpackChunk=self.webpackChunk||[]).push([[7979],{"../node_modules/mini-css-extract-plugin/dist/loader.js??clonedRuleSet-13.use[1]!../node_modules/css-loader/dist/cjs.js??clonedRuleSet-13.use[2]!../node_modules/vue-loader/lib/loaders/stylePostLoader.js!../node_modules/postcss-loader/dist/cjs.js??clonedRuleSet-13.use[3]!../node_modules/sass-loader/dist/cjs.js??clonedRuleSet-13.use[4]!../node_modules/vue-loader/lib/index.js??vue-loader-options!../node_modules/unplugin/dist/webpack/loaders/transform.js?unpluginName=unplugin-vue-define-options!./js/pages/admin/backups/restore.vue?vue&type=style&index=0&id=52beb5d0&prod&lang=scss&scoped=true&":function(){},"./js/pages/admin/backups/restore.vue":function(l,a,n){"use strict";n.r(a),n.d(a,{default:function(){return x}});var o=function(){var e=this,t=e._self._c;return t("app-page",{attrs:{id:"restore-admin-backup"},scopedSlots:e._u([{key:"default",fn:function(){return[t("app-page-section",[t("ui-steps",{attrs:{steps:[{id:"where",label:e.$gettext("Step 1: From Where"),desc:e.$gettext("Select directory for restore."),completed:e.validWhere},{id:"ip_select",label:e.$gettext("Step 2: Select IP"),desc:e.$gettext("Select IP address used for restore.")},{id:"files",label:e.$gettext("Step 3: Select File(s)"),desc:e.$gettext("Select backup files to restore."),completed:e.validFiles}],current:e.step},on:{"update:current":function(s){e.step=s}},scopedSlots:e._u([{key:"buttons",fn:function(){return[e.step==="where"?t("ui-button",{key:"reloadFiles",attrs:{theme:"primary"},on:{click:e.reloadFiles}},[t("span",{domProps:{textContent:e._s(e.$gettext("Reload Files"))}})]):e.step==="files"?t("ui-button",{key:"restoreBackup",attrs:{theme:"safe",disabled:!(e.validFiles&&e.validWhere)},on:{click:e.restoreBackup}},[t("span",{domProps:{textContent:e._s(e.$gettext("Restore"))}})]):e._e()]},proxy:!0},{key:"step:where",fn:function(){return[t("div",{key:"where"},[t("ui-form-element",{attrs:{"vertical-on-phone":!1,reverse:e.clientStore.isPhone},scopedSlots:e._u([{key:"title",fn:function(){return[t("span",{domProps:{textContent:e._s(e.$gettext("Local"))}})]},proxy:!0},{key:"content",fn:function(){return[t("input-radio",{attrs:{value:"local"},model:{value:e.where,callback:function(s){e.where=s},expression:"where"}})]},proxy:!0}])}),e._v(" "),t("transition",{attrs:{name:"fade"}},[e.where==="local"?t("ui-form-element",{attrs:{group:"restoreBackupWhere",validators:{required:!0}},scopedSlots:e._u([{key:"title",fn:function(){return[t("span",{domProps:{textContent:e._s(e.$gettext("Path"))}})]},proxy:!0},{key:"content",fn:function(){return[t("input-text",{model:{value:e.whereData.local_path,callback:function(s){e.$set(e.whereData,"local_path",s)},expression:"whereData.local_path"}})]},proxy:!0}],null,!1,1026019078)}):e._e()],1),e._v(" "),t("ui-form-element",{attrs:{underline:e.where==="ftp","vertical-on-phone":!1,reverse:e.clientStore.isPhone},scopedSlots:e._u([{key:"title",fn:function(){return[t("span",{domProps:{textContent:e._s(e.$gettext("FTP"))}})]},proxy:!0},{key:"content",fn:function(){return[t("input-radio",{attrs:{value:"ftp"},model:{value:e.where,callback:function(s){e.where=s},expression:"where"}})]},proxy:!0}])}),e._v(" "),t("transition",{attrs:{name:"fade"}},[e.where==="ftp"?t("ui-form-element",{attrs:{underline:!1},scopedSlots:e._u([{key:"title",fn:function(){return[t("span",{domProps:{textContent:e._s(e.$gettext("FTP Settings"))}})]},proxy:!0},{key:"content",fn:function(){return[t("div",[t("ui-form-element",{attrs:{group:"restoreBackupWhere",validators:{required:!0}},scopedSlots:e._u([{key:"title",fn:function(){return[t("span",{domProps:{textContent:e._s(e.$gettext("IP"))}})]},proxy:!0},{key:"content",fn:function(){return[t("input-text",{model:{value:e.whereData.ftp_ip,callback:function(s){e.$set(e.whereData,"ftp_ip",s)},expression:`
                                                        whereData.ftp_ip
                                                    `}})]},proxy:!0}],null,!1,2098599785)}),e._v(" "),t("ui-form-element",{attrs:{group:"restoreBackupWhere",validators:{required:!0}},scopedSlots:e._u([{key:"title",fn:function(){return[t("span",{domProps:{textContent:e._s(e.$gettext("Username"))}})]},proxy:!0},{key:"content",fn:function(){return[t("input-text",{model:{value:e.whereData.ftp_username,callback:function(s){e.$set(e.whereData,"ftp_username",s)},expression:`
                                                        whereData.ftp_username
                                                    `}})]},proxy:!0}],null,!1,1789493801)}),e._v(" "),t("ui-form-element",{attrs:{group:"restoreBackupWhere",validators:{required:!0}},scopedSlots:e._u([{key:"title",fn:function(){return[t("span",{domProps:{textContent:e._s(e.$gettext("Password"))}})]},proxy:!0},{key:"content",fn:function(){return[t("input-password",{model:{value:e.whereData.ftp_password,callback:function(s){e.$set(e.whereData,"ftp_password",s)},expression:`
                                                        whereData.ftp_password
                                                    `}})]},proxy:!0}],null,!1,1001378347)}),e._v(" "),t("ui-form-element",{attrs:{group:"restoreBackupWhere",validators:{required:!0}},scopedSlots:e._u([{key:"title",fn:function(){return[t("span",{domProps:{textContent:e._s(e.$gettext("Remote Path"))}})]},proxy:!0},{key:"content",fn:function(){return[t("input-text",{model:{value:e.whereData.ftp_path,callback:function(s){e.$set(e.whereData,"ftp_path",s)},expression:`
                                                        whereData.ftp_path
                                                    `}})]},proxy:!0}],null,!1,1387663809)}),e._v(" "),t("ui-form-element",{attrs:{group:"restoreBackupWhere",validators:{required:!0}},scopedSlots:e._u([{key:"title",fn:function(){return[t("span",{domProps:{textContent:e._s(e.$gettext("Port"))}})]},proxy:!0},{key:"content",fn:function(){return[t("input-text",{attrs:{number:""},model:{value:e.whereData.ftp_port,callback:function(s){e.$set(e.whereData,"ftp_port",s)},expression:`
                                                        whereData.ftp_port
                                                    `}})]},proxy:!0}],null,!1,1697913984)}),e._v(" "),t("ui-form-element",{attrs:{"vertical-on-phone":!1,reverse:e.clientStore.isPhone},scopedSlots:e._u([{key:"title",fn:function(){return[t("span",{domProps:{textContent:e._s(e.$gettext("Secure FTP"))}})]},proxy:!0},{key:"content",fn:function(){return[t("input-checkbox",{model:{value:e.whereData.ftp_secure,callback:function(s){e.$set(e.whereData,"ftp_secure",s)},expression:`
                                                        whereData.ftp_secure
                                                    `}})]},proxy:!0}],null,!1,1560989257)})],1)]},proxy:!0}],null,!1,2543142875)}):e._e()],1)],1)]},proxy:!0},{key:"step:ip_select",fn:function(){return[t("div",{key:"ip_select"},[t("ui-form-element",{attrs:{underline:e.ip_choice==="select"},scopedSlots:e._u([{key:"title",fn:function(){return[t("span",{domProps:{textContent:e._s(e.$gettext("Use the IP"))}})]},proxy:!0},{key:"content",fn:function(){return[t("div",{directives:[{name:"flex",rawName:"v-flex",value:{dir:e.clientStore.isPhone?"column":"row"},expression:`{
                                        dir: clientStore.isPhone
                                            ? 'column'
                                            : 'row',
                                    }`},{name:"gutter",rawName:"v-gutter",value:1,expression:"1"}]},[t("input-radio",{attrs:{value:"file"},model:{value:e.ip_choice,callback:function(s){e.ip_choice=s},expression:"ip_choice"}},[t("span",{domProps:{textContent:e._s(e.$gettext("stored in the backup"))}})]),e._v(" "),t("input-radio",{attrs:{value:"select"},model:{value:e.ip_choice,callback:function(s){e.ip_choice=s},expression:"ip_choice"}},[t("span",{domProps:{textContent:e._s(e.$gettext("from the list"))}})])],1)]},proxy:!0}])}),e._v(" "),t("transition",{attrs:{name:"fade"}},[e.ip_choice==="select"?t("ui-form-element",{attrs:{underline:!1},scopedSlots:e._u([{key:"title",fn:function(){return[t("span",{domProps:{textContent:e._s(e.$gettext("IP"))}})]},proxy:!0},{key:"content",fn:function(){return[t("input-select",{attrs:{options:e.options.ips.options},model:{value:e.ipSelectData.ip,callback:function(s){e.$set(e.ipSelectData,"ip",s)},expression:"ipSelectData.ip"}})]},proxy:!0}],null,!1,2085228877)}):e._e()],1),e._v(" "),t("transition",{attrs:{name:"fade"}},[e.$api.options.filesData.home_override?t("ui-form-element",{scopedSlots:e._u([{key:"title",fn:function(){return[t("span",{domProps:{textContent:e._s(e.$gettext("Restore to partition"))}})]},proxy:!0},{key:"content",fn:function(){return[t("input-select",{attrs:{options:e.$api.options.filesData.home_override.options},model:{value:e.ipSelectData.create_user_home_override,callback:function(s){e.$set(e.ipSelectData,"create_user_home_override",s)},expression:`
                                            ipSelectData.create_user_home_override
                                        `}})]},proxy:!0}],null,!1,206006384)}):e._e()],1),e._v(" "),t("ul",[t("li",{domProps:{textContent:e._s(e.$gettext("Note that you must set the IP to be shared if you want to add multiple users to it. If you select a non-shared IP, you can only restore 1 user to it."))}}),e._v(" "),t("li",{domProps:{textContent:e._s(e.$gettext("If the user already exists, this setting will have no effect."))}}),e._v(" "),t("li",{domProps:{textContent:e._s(e.$gettext("When restoring a Reseller or Admin, if you select an IP from the list, that Reseller will only receive the single IP. You would need to add extra IPs to that accounts IP list after he's created."))}}),e._v(" "),t("li",{domProps:{textContent:e._s(e.$gettext("If using the IPs from within the backup, any IPs that don't exist on this system will not be included. If there no IPs to be used, a Reseller or Admin will be restored to the server IP."))}})])],1)]},proxy:!0},{key:"step:files",fn:function(){return[t("div",{key:"files"},[t("ui-form-element",{scopedSlots:e._u([{key:"title",fn:function(){return[t("span",{domProps:{textContent:e._s(e.$gettext("Location"))}})]},proxy:!0},{key:"content",fn:function(){return[t("input-text",{attrs:{disabled:"",value:e.files.location}})]},proxy:!0}])}),e._v(" "),t("ui-form-element",{attrs:{underline:e.encryptionEnabled},scopedSlots:e._u([{key:"title",fn:function(){return[t("span",{domProps:{textContent:e._s(e.$gettext("Files"))}})]},proxy:!0},{key:"content",fn:function(){return[t("input-select-multiple",{staticClass:"width:100%",attrs:{options:e.filesList,"disabled-entries":e.disabledFiles},scopedSlots:e._u([e._l(e.issues,function(s){return{key:`option:${s.file}`,fn:function(){return[t("ui-tooltip",{key:s.file,attrs:{theme:"danger"},scopedSlots:e._u([{key:"trigger",fn:function(){return[t("span",{staticClass:"c:txt:danger"},[e._v(`
                                                    `+e._s(s.file)+`
                                                `)])]},proxy:!0}],null,!0)},[e._v(" "),e._l(s.issues,function(p){return t("li",{key:p,attrs:{theme:"danger"},domProps:{innerHTML:e._s(p)}})})],2)]},proxy:!0}})],null,!0),model:{value:e.selectedFiles,callback:function(s){e.selectedFiles=s},expression:"selectedFiles"}})]},proxy:!0}])}),e._v(" "),t("ui-form-element",{scopedSlots:e._u([{key:"title",fn:function(){return[t("span",{domProps:{textContent:e._s(e.$gettext("Assign to Reseller"))}})]},proxy:!0},{key:"content",fn:function(){return[t("input-select",{attrs:{options:e.resellerOverrideOptions},model:{value:e.reseller_override,callback:function(s){e.reseller_override=s},expression:"reseller_override"}})]},proxy:!0}])}),e._v(" "),e.encryptionEnabled?[t("ui-form-element",{attrs:{underline:e.decrypt,"vertical-on-phone":!1,reverse:e.clientStore.isPhone},scopedSlots:e._u([{key:"title",fn:function(){return[t("span",{domProps:{textContent:e._s(e.$gettext("Backup Decryption"))}})]},proxy:!0},{key:"content",fn:function(){return[t("input-checkbox",{model:{value:e.decrypt,callback:function(s){e.decrypt=s},expression:"decrypt"}})]},proxy:!0}],null,!1,3596436891)}),e._v(" "),t("transition",{attrs:{name:"fadeBounce"}},[e.decrypt?t("ui-form-element",{attrs:{underline:!1,group:"scheduleBackup",validators:{required:!0}},scopedSlots:e._u([{key:"title",fn:function(){return[t("span",{domProps:{textContent:e._s(e.$gettext("Password"))}})]},proxy:!0},{key:"content",fn:function(){return[t("input-password",{model:{value:e.password,callback:function(s){e.password=s},expression:"password"}})]},proxy:!0}],null,!1,3464064881)}):e._e()],1)]:e._e()],2)]},proxy:!0}])})],1)]},proxy:!0}])})},u=[],d=n("./js/stores/index.ts"),i=n("./js/api/commands/admin/backups/index.js"),c=n("./js/vue-globals/mixins.js"),f={preload:[i.pZ,i.v6],mixins:[(0,c.$bindTab)({defaultTab:"where",param:"step"})],data(){return{where:"local",whereData:{local_path:"",ftp_ip:"",ftp_username:"",ftp_password:"",ftp_path:"",ftp_port:"",ftp_secure:""},ip_choice:"select",ipSelectData:{ip:"",create_user_home_override:""},checkedRows:[],decrypt:!1,password:"",selectedFiles:[],reseller_override:""}},api:[{command:i.pZ,bind:"options"},{command:i.Fi,bind:{response:"files",isDone:"filesLoaded"}},{command:i.v6,bind:"encryption"}],computed:{validWhere(){return this.where==="local"&&!!this.whereData.local_path||this.where==="ftp"&&!!this.whereData.ftp_ip&&!!this.whereData.ftp_username&&!!this.whereData.ftp_password&&!!this.whereData.ftp_path&&!!this.whereData.ftp_port},validFiles(){if(this.decrypt&&!this.password)return!1;if(this.selectedFiles.length){const{issues:r={}}=this.files;return this.selectedFiles.every(e=>!r[e])}return!1},options(){return this.$api.options},files(){return this.$api.filesLoaded?this.$api.files:this.$api.options.filesData},encryptionEnabled(){return this.$api.encryption.enabled},issues(){return this.files.list.filter(r=>r.issues)},checkedFiles(){return this.checkedRows.map(r=>r.file)},requestData(){return{where:this.where,...this.whereData,ip_choice:this.ip_choice,...this.ipSelectData,select:this.selectedFiles,encryption_password:this.password,ftp_secure:this.whereData.ftp_secure?"ftps":"no",reseller_override:this.reseller_override||null}},filesList(){return this.files.list.map(({file:r})=>r)},disabledFiles(){return this.files.list.filter(({disabled:r})=>r).map(({file:r})=>r)},resellerOverrideOptions(){return Object.keys(this.$api.options.data_list||{})},...(0,d.Kc)(["client"])},watch:{step(r,e){e==="where"&&this.reloadFiles()}},created(){this.where=this.options.where,Object.assign(this.whereData,this.options.whereData),this.ipSelectData.ip=this.options.ips.value,this.$api.options.filesData.home_override&&(this.ipSelectData.create_user_home_override=this.$api.options.filesData.home_override.value)},methods:{reloadFiles(){(0,i.Fi)({where:this.where,...this.whereData,ftp_secure:this.whereData.ftp_secure?"ftps":"no"})},async restoreBackup(){await(0,i.pi)(this.requestData)&&this.$router.push({name:"admin/backups"})}}},m=f,v=n("../node_modules/vue-style-loader/index.js!../node_modules/mini-css-extract-plugin/dist/loader.js??clonedRuleSet-13.use[1]!../node_modules/css-loader/dist/cjs.js??clonedRuleSet-13.use[2]!../node_modules/vue-loader/lib/loaders/stylePostLoader.js!../node_modules/postcss-loader/dist/cjs.js??clonedRuleSet-13.use[3]!../node_modules/sass-loader/dist/cjs.js??clonedRuleSet-13.use[4]!../node_modules/vue-loader/lib/index.js??vue-loader-options!../node_modules/unplugin/dist/webpack/loaders/transform.js?unpluginName=unplugin-vue-define-options!./js/pages/admin/backups/restore.vue?vue&type=style&index=0&id=52beb5d0&prod&lang=scss&scoped=true&"),h=n("../node_modules/vue-loader/lib/runtime/componentNormalizer.js"),_=(0,h.Z)(m,o,u,!1,null,"52beb5d0",null),x=_.exports},"../node_modules/vue-style-loader/index.js!../node_modules/mini-css-extract-plugin/dist/loader.js??clonedRuleSet-13.use[1]!../node_modules/css-loader/dist/cjs.js??clonedRuleSet-13.use[2]!../node_modules/vue-loader/lib/loaders/stylePostLoader.js!../node_modules/postcss-loader/dist/cjs.js??clonedRuleSet-13.use[3]!../node_modules/sass-loader/dist/cjs.js??clonedRuleSet-13.use[4]!../node_modules/vue-loader/lib/index.js??vue-loader-options!../node_modules/unplugin/dist/webpack/loaders/transform.js?unpluginName=unplugin-vue-define-options!./js/pages/admin/backups/restore.vue?vue&type=style&index=0&id=52beb5d0&prod&lang=scss&scoped=true&":function(l,a,n){var o=n("../node_modules/mini-css-extract-plugin/dist/loader.js??clonedRuleSet-13.use[1]!../node_modules/css-loader/dist/cjs.js??clonedRuleSet-13.use[2]!../node_modules/vue-loader/lib/loaders/stylePostLoader.js!../node_modules/postcss-loader/dist/cjs.js??clonedRuleSet-13.use[3]!../node_modules/sass-loader/dist/cjs.js??clonedRuleSet-13.use[4]!../node_modules/vue-loader/lib/index.js??vue-loader-options!../node_modules/unplugin/dist/webpack/loaders/transform.js?unpluginName=unplugin-vue-define-options!./js/pages/admin/backups/restore.vue?vue&type=style&index=0&id=52beb5d0&prod&lang=scss&scoped=true&");o.__esModule&&(o=o.default),typeof o=="string"&&(o=[[l.id,o,""]]),o.locals&&(l.exports=o.locals);var u=n("../node_modules/vue-style-loader/lib/addStylesClient.js").Z,d=u("6315e12a",o,!0,{})}}]);