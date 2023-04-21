"use strict";(self.webpackChunk=self.webpackChunk||[]).push([[2301],{"../node_modules/date-fns/esm/formatDistance/index.js":function(b,O,a){a.d(O,{Z:function(){return X}});var E=a("../node_modules/date-fns/esm/_lib/defaultOptions/index.js"),s=a("../node_modules/date-fns/esm/toDate/index.js"),l=a("../node_modules/date-fns/esm/_lib/requiredArgs/index.js");function v(r,t){(0,l.Z)(2,arguments);var e=(0,s.Z)(r),f=(0,s.Z)(t),m=e.getTime()-f.getTime();return m<0?-1:m>0?1:m}function I(r,t){(0,l.Z)(2,arguments);var e=(0,s.Z)(r),f=(0,s.Z)(t),m=e.getFullYear()-f.getFullYear(),Z=e.getMonth()-f.getMonth();return m*12+Z}function h(r){(0,l.Z)(1,arguments);var t=(0,s.Z)(r);return t.setHours(23,59,59,999),t}function _(r){(0,l.Z)(1,arguments);var t=(0,s.Z)(r),e=t.getMonth();return t.setFullYear(t.getFullYear(),e+1,0),t.setHours(23,59,59,999),t}function D(r){(0,l.Z)(1,arguments);var t=(0,s.Z)(r);return h(t).getTime()===_(t).getTime()}function x(r,t){(0,l.Z)(2,arguments);var e=(0,s.Z)(r),f=(0,s.Z)(t),m=v(e,f),Z=Math.abs(I(e,f)),o;if(Z<1)o=0;else{e.getMonth()===1&&e.getDate()>27&&e.setDate(30),e.setMonth(e.getMonth()-m*Z);var P=v(e,f)===-m;D((0,s.Z)(r))&&Z===1&&v(r,f)===1&&(P=!1),o=m*(Z-Number(P))}return o===0?0:o}function j(r,t){return(0,l.Z)(2,arguments),(0,s.Z)(r).getTime()-(0,s.Z)(t).getTime()}var M={ceil:Math.ceil,round:Math.round,floor:Math.floor,trunc:function(t){return t<0?Math.ceil(t):Math.floor(t)}},d="trunc";function p(r){return r?M[r]:M[d]}function R(r,t,e){(0,l.Z)(2,arguments);var f=j(r,t)/1e3;return p(e==null?void 0:e.roundingMethod)(f)}var L=a("../node_modules/date-fns/esm/_lib/defaultLocale/index.js");function B(r,t){if(r==null)throw new TypeError("assign requires that input parameter not be null or undefined");for(var e in t)Object.prototype.hasOwnProperty.call(t,e)&&(r[e]=t[e]);return r}function W(r){return B({},r)}var n=a("../node_modules/date-fns/esm/_lib/getTimezoneOffsetInMilliseconds/index.js"),i=1440,g=2520,T=43200,S=86400;function X(r,t,e){var f,m;(0,l.Z)(2,arguments);var Z=(0,E.j)(),o=(f=(m=e==null?void 0:e.locale)!==null&&m!==void 0?m:Z.locale)!==null&&f!==void 0?f:L.Z;if(!o.formatDistance)throw new RangeError("locale must contain formatDistance property");var P=v(r,t);if(isNaN(P))throw new RangeError("Invalid time value");var u=B(W(e),{addSuffix:Boolean(e==null?void 0:e.addSuffix),comparison:P}),N,U;P>0?(N=(0,s.Z)(t),U=(0,s.Z)(r)):(N=(0,s.Z)(r),U=(0,s.Z)(t));var y=R(U,N),F=((0,n.Z)(U)-(0,n.Z)(N))/1e3,c=Math.round((y-F)/60),A;if(c<2)return e!=null&&e.includeSeconds?y<5?o.formatDistance("lessThanXSeconds",5,u):y<10?o.formatDistance("lessThanXSeconds",10,u):y<20?o.formatDistance("lessThanXSeconds",20,u):y<40?o.formatDistance("halfAMinute",0,u):y<60?o.formatDistance("lessThanXMinutes",1,u):o.formatDistance("xMinutes",1,u):c===0?o.formatDistance("lessThanXMinutes",1,u):o.formatDistance("xMinutes",c,u);if(c<45)return o.formatDistance("xMinutes",c,u);if(c<90)return o.formatDistance("aboutXHours",1,u);if(c<i){var Y=Math.round(c/60);return o.formatDistance("aboutXHours",Y,u)}else{if(c<g)return o.formatDistance("xDays",1,u);if(c<T){var z=Math.round(c/i);return o.formatDistance("xDays",z,u)}else if(c<S)return A=Math.round(c/T),o.formatDistance("aboutXMonths",A,u)}if(A=x(U,N),A<12){var H=Math.round(c/T);return o.formatDistance("xMonths",H,u)}else{var $=A%12,C=Math.floor(A/12);return $<3?o.formatDistance("aboutXYears",C,u):$<9?o.formatDistance("overXYears",C,u):o.formatDistance("almostXYears",C+1,u)}}},"./js/composables/dateFilter.ts":function(b,O,a){a.d(O,{W:function(){return I},f:function(){return l.f}});var E=a("../node_modules/ramda/es/index.js"),s=a("../node_modules/date-fns/esm/format/index.js"),l=a("./js/modules/date-formats.ts"),v=a("./js/modules/customizations/date-formats/default.ts");const I=E.WAo((h,_)=>{if(_)try{return(0,s.Z)(_,l.f.value[h])}catch(D){return console.warn(`Given ${h} format is incorrect:
${D.message}`),(0,s.Z)(_,v.d[h])}return""})},"./js/composables/filters.ts":function(b,O,a){a.d(O,{Q0:function(){return R},aS:function(){return B},d5:function(){return L},eB:function(){return M},hT:function(){return x},kC:function(){return D},n9:function(){return p},zM:function(){return j}});var E=a("../node_modules/date-fns/esm/formatDistance/index.js"),s=a("../node_modules/punycode/punycode.es6.js"),l=a("./js/composables/dateFilter.ts"),v=a("./js/composables/gettext.ts");const{$gettext:I,$ngettext:h,$gettextInterpolate:_}=(0,v.Z)(),D=n=>{var i;return n?((i=n.at(0))===null||i===void 0?void 0:i.toUpperCase())+n.slice(1):""},x=(n,i="datetime")=>(0,l.W)(i,n),j=n=>(0,E.Z)(n,new Date),M=(n,i=1024)=>{const g=Number(n);if(!g)return"0 B";const T=["B","KB","MB","GB","TB","PB","EB","ZB","YB"],S=Math.floor(Math.log(g)/Math.log(i));return`${parseFloat((g/i**S).toFixed(2))} ${T[S]}`},d=n=>{try{return(0,s.xX)(n)}catch(i){return n}},p=n=>(0,s.xX)(n),R=n=>{if(!n||!n.includes("@"))return n;const[i,g]=n.split("@");return[i,d(g)].join("@")},L=n=>{if(n<60)return I("less than a minute");const i=Math.floor(n/60)%60,g=Math.floor(n/3600)%24,T=Math.floor(n/(3600*24)),S=[T?h("%{days} day","%{days} days",T):null,g?h("%{hours} hour","%{hours} hours",g):null,i?h("%{minutes} minute","%{minutes} minutes",i):null].filter(Boolean).join(", ");return _(S,{days:T,hours:g,minutes:i})},B=(n,i)=>n.length<=i?n:`${n.substring(0,i)}...`,W=()=>({capitalize:D,date:x,distanceFromNow:j,humanReadableSize:M,p6eUnicode:p,p6eUnicodeEmail:R,formatUptime:L,truncateString:B})},"./js/pages/user/login-history.vue":function(b,O,a){a.r(O),a.d(O,{default:function(){return j}});var E=function(){var d=this,p=d._self._c;return p("app-page",[p("app-page-section",[p("ui-api-table",d._b({attrs:{"equal-width-layout":"","hide-before-controls":""},scopedSlots:d._u([{key:"col:date",fn:function({date:R}){return[d._v(`
                `+d._s(d.date(R,"datetime"))+`
            `)]}}])},"ui-api-table",{command:d.$commands.getHistory,endpoint:"GET_LOGIN_HISTORY",columns:{date:d.$gettext("Date"),ip:d.$gettext("IP"),attempts:d.$gettext("Attempts")},disableSelect:!0},!1))],1)],1)},s=[],l=a("./js/api/command/index.js"),v=l.Z.get({id:"LOGIN_HISTORY",url:"/CMD_LOGIN_HISTORY",pagination:!0,after:M=>M.toTable(M.mapArrayProps({date:d=>M.convert.toAppDate(d.timestamp)}))}),I=a("./js/composables/filters.ts"),h={preload:v,commands:{getHistory:v},methods:{date:I.hT}},_=h,D=a("../node_modules/vue-loader/lib/runtime/componentNormalizer.js"),x=(0,D.Z)(_,E,s,!1,null,null,null),j=x.exports}}]);