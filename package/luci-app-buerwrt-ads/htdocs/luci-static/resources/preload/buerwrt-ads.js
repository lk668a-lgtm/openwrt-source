/*
 * SPDX-License-Identifier: GPL-3.0
 * buerwrt-ads preload 钩子
 *
 * LuCI 的 luci.js 会自动加载 <resource>/preload/*.js 下的所有类并在 DOM
 * 就绪后实例化（见 luci.js probePreloadClasses / setupDOM）。本文件借助这
 * 一机制实现两件事，全程不改 luci-app-tkproxy 的任何文件：
 *
 *   1. 按 uci 配置决定「服务 → 资源推荐」菜单项与概览页卡片的去留：
 *      每次页面加载都请求一次本插件自己的 config 端点（no-store，不吃缓存），
 *      enabled=0 时移除菜单里的入口、跳过注入；enabled=1 时把菜单缓存里
 *      被旧状态标灰的项恢复回来。
 *   2. 在 luci-app-tkproxy 的概览页（data-tk-page="dashboard"）底部注入
 *      与独立页同款的资源卡片。找不到目标就安静退出，绝不报错打扰别的页面。
 *
 * 安全：所有动态文本一律 textContent / createElement，不拼 innerHTML；
 * 链接固定 rel="noopener noreferrer"；不加载任何外链资源。
 */
'require baseclass';
'require ui';

return baseclass.extend({
	__init__: function () {
		document.addEventListener('DOMContentLoaded', this.run.bind(this));
		/* luci.js 的 DOMContentLoaded 监听可能晚于本文件注册（preload 先于
		 * ui/form 加载完成），readyState 兜底保证不漏触发。 */
		if (document.readyState !== 'loading') {
			this.run();
		}
	},

	run: function () {
		if (this._ran) { return; }
		this._ran = true;

		var apply = function (cfg) {
			this._cfg = cfg;
			this.applyMenu(cfg);
			this.injectCard(cfg);
		}.bind(this);

		this.fetchConfig()
			.then(apply)
			.catch(function () {
				/* 配置拉不到（比如插件被卸载残留）：按关闭处理，菜单不显示 */
				apply({ enabled: false });
			});

		/* 主题菜单在 luci-loaded 后才渲染，上面第一趟可能跑在渲染之前；
		 * 这里用第一趟缓存的配置再兜一次底（removeMenuDom / injectCard 幂等）。 */
		document.addEventListener('luci-loaded', function () {
			if (this._loadedRan) { return; }
			this._loadedRan = true;
			var cfg = this._cfg;
			if (cfg) { this.applyMenu(cfg); this.injectCard(cfg); }
		}.bind(this));
	},

	fetchConfig: function () {
		/* config 端点由本插件控制器提供；L.url 生成 /cgi-bin/luci/... 前缀 */
		var url = L.url('admin/services/buerwrtads/config');
		return window.fetch(url, {
			method: 'GET',
			credentials: 'same-origin',
			cache: 'no-store'
		}).then(function (res) {
			if (!res.ok) { throw new Error('HTTP ' + res.status); }
			return res.json();
		});
	},

	/* ------------------------------------------------ 菜单可见性 */

	applyMenu: function (cfg) {
		var enabled = !!(cfg && cfg.enabled);

		/* 菜单可见性以服务端为准：menu.d depends.uci 在页面树里求值，
		 * 保存端点已同步清 /tmp/luci-indexcache.*，所以服务端菜单始终
		 * 新鲜。这里只处理浏览器侧的两个残留：
		 *   1) ui.menu 的 sessionStorage 缓存（按 SID 缓存，切换后不失效）
		 *      —— 缓存内容与服务端状态不一致时 flush 一次；
		 *   2) 已渲染的 DOM —— 直接隐藏（幂等）。 */

		if (window.L && L.ui && L.ui.menu) {
			var cached = this.menuHasEntry(L.ui.menu.menu);
			if (cached !== null && cached !== enabled) {
				try { L.ui.menu.flushCache(); } catch (e) { /* 忽略 */ }
			}
		}

		if (!enabled) {
			this.removeMenuDom();
		}
	},

	/* 缓存菜单树里是否含 buerwrtads 入口；缓存不存在/结构异常返回 null */
	menuHasEntry: function (tree) {
		try {
			var svc = tree &&
				tree.children && tree.children.admin &&
				tree.children.admin.children &&
				tree.children.admin.children.services &&
				tree.children.admin.children.services.children;
			if (!svc) { return null; }
			if (!svc.buerwrtads) { return false; }
			return !!svc.buerwrtads.satisfied;
		} catch (e) {
			return null;
		}
	},

	removeMenuDom: function () {
		var links = document.querySelectorAll('a[href*="buerwrtads"]');
		for (var i = 0; i < links.length; i++) {
			var li = links[i].closest ? links[i].closest('li') : null;
			(li || links[i]).style.display = 'none';
		}
	},

	/* ------------------------------------------------ 概览页卡片注入 */

	injectCard: function (cfg) {
		if (!cfg || !cfg.enabled) { return; }

		/* 按 data 属性判定页面：只认 tkproxy 概览页，找不到就安静退出 */
		var tkroot = document.querySelector('[data-tk-page="dashboard"]');
		if (!tkroot || document.querySelector('[data-buads-card]')) { return; }

		this.ensureCss();

		var card = document.createElement('div');
		card.className = 'buads-wrap buads-embed';
		card.setAttribute('data-buads-card', '1');

		var head = document.createElement('div');
		head.className = 'buads-eyebrow';
		head.textContent = 'BUERWRT · 资源推荐';

		var hero = document.createElement('div');
		hero.className = 'buads-hero';

		var icon = document.createElement('div');
		icon.className = 'buads-hero-icon';
		icon.setAttribute('aria-hidden', 'true');
		icon.appendChild(this.buildIcon());

		var main = document.createElement('div');
		main.className = 'buads-hero-main';

		var title = document.createElement('h3');
		title.className = 'buads-hero-title';
		title.textContent = cfg.title || 'TK 各种资源';

		var sub = document.createElement('p');
		sub.className = 'buads-hero-sub';
		sub.textContent = '精选 TIKTOK 相关资源与服务入口，点击前往查看。';

		main.appendChild(title);
		main.appendChild(sub);

		var actions = document.createElement('div');
		actions.className = 'buads-hero-actions';

		var a = document.createElement('a');
		a.className = 'buads-btn';
		a.href = cfg.url || 'https://buerai.net';
		a.rel = 'noopener noreferrer';
		a.target = (cfg.open_in_new_tab === false) ? '_self' : '_blank';
		a.textContent = '前往 →';

		actions.appendChild(a);
		hero.appendChild(icon);
		hero.appendChild(main);
		hero.appendChild(actions);
		card.appendChild(head);
		card.appendChild(hero);

		tkroot.appendChild(card);
	},

	/* 卡片样式表：只在本插件自己的静态目录取，纯本地无外链；
	 * 幂等：已存在就不重复插入。 */
	ensureCss: function () {
		if (document.querySelector('link[data-buads-css]')) { return; }
		var link = document.createElement('link');
		link.rel = 'stylesheet';
		link.href = L.resource('buerwrt-ads/ads.css') + '?v=1.0.0';
		link.setAttribute('data-buads-css', '1');
		document.head.appendChild(link);
	},

	/* 网格图标：内联 SVG，纯 DOM 构建，无 innerHTML */
	buildIcon: function () {
		var NS = 'http://www.w3.org/2000/svg';
		var svg = document.createElementNS(NS, 'svg');
		svg.setAttribute('viewBox', '0 0 24 24');
		svg.setAttribute('width', '40');
		svg.setAttribute('height', '40');
		svg.setAttribute('focusable', 'false');

		var paths = [
			['M4 4h7v7H4zM13 4h7v7h-7zM4 13h7v7H4zM13 13h7v7h-7z', '.18'],
			['M5 6.5 9.5 4v5zM14.5 4 19 6.5 14.5 9zM5 15.5 9.5 13v5zM14.5 13 19 15.5 14.5 18z', '1']
		];
		paths.forEach(function (p) {
			var el = document.createElementNS(NS, 'path');
			el.setAttribute('fill', 'currentColor');
			el.setAttribute('d', p[0]);
			el.setAttribute('opacity', p[1]);
			svg.appendChild(el);
		});
		return svg;
	}
});
