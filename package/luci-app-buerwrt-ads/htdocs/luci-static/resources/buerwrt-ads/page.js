/*
 * SPDX-License-Identifier: GPL-3.0
 * buerwrt-ads 页面交互（开关）
 *
 * 约定（与 tkproxy app.js 同一套）：
 *   - 动态文本一律 textContent，不拼 innerHTML；
 *   - 写操作 POST 到 save 端点，CSRF token 由 Dispatcher 校验；
 *   - token 取 LuCI.env.token（与 LuCI 自身 POST 一致）。
 */
(function () {
	'use strict';

	var root = document.querySelector('[data-buads-page]');
	if (!root) { return; }

	var saveUrl = root.getAttribute('data-buads-save') || '';
	var toggle = root.querySelector('[data-buads-toggle]');
	var out = root.querySelector('[data-buads-out]');

	function setText(node, text, cls) {
		if (!node) { return; }
		node.textContent = text;
		node.className = 'buads-out' + (cls ? ' ' + cls : '');
	}

	function post(body) {
		var data = new URLSearchParams();
		/* LuCI 自身 POST 也带 env.token（= ctx.authtoken，Dispatcher 校验值） */
		data.set('token', (window.L && window.L.env && window.L.env.token) || '');
		Object.keys(body).forEach(function (k) { data.set(k, body[k]); });
		return fetch(saveUrl, {
			method: 'POST',
			credentials: 'same-origin',
			cache: 'no-store',
			headers: { 'Content-Type': 'application/x-www-form-urlencoded; charset=UTF-8' },
			body: data.toString()
		}).then(function (res) {
			return res.json().catch(function () { throw new Error('HTTP ' + res.status); });
		});
	}

	if (!toggle) { return; }

	toggle.addEventListener('click', function () {
		var cur = toggle.getAttribute('data-buads-enabled') === '1';
		var next = cur ? '0' : '1';

		toggle.disabled = true;
		setText(out, '保存中…', '');

		post({ enabled: next }).then(function (r) {
			if (!r || !r.ok) {
				setText(out, (r && r.msg) ? r.msg : '保存失败', 'is-err');
				toggle.disabled = false;
				return;
			}
			toggle.setAttribute('data-buads-enabled', next);
			toggle.textContent = next === '1' ? '启用中' : '已关闭';
			setText(out, '已保存，刷新页面后生效', 'is-ok');
			toggle.disabled = false;
			window.setTimeout(function () { window.location.reload(); }, 800);
		}).catch(function (e) {
			setText(out, '保存失败：' + e.message, 'is-err');
			toggle.disabled = false;
		});
	});
})();
