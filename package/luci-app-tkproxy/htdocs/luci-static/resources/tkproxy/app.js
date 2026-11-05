/*
 * SPDX-License-Identifier: GPL-3.0
 * tkproxy 页面交互
 *
 * 约定：
 *   - 所有动态文本一律用 textContent 写入，不拼 innerHTML；
 *   - 模板里只放 data-* 属性，本文件负责事件委托；
 *   - 写操作统一 POST 到 <base>/action，并带上 CSRF token。
 */
(function () {
	'use strict';

	var root = document.querySelector('[data-tk-page]');
	if (!root) { return; }

	var page = root.getAttribute('data-tk-page');
	var base = root.getAttribute('data-tk-base') || '';
	var token = root.getAttribute('data-tk-token') || '';
	var deployed = root.getAttribute('data-tk-deployed') === '1';
	// 服务端渲染时是否已有部署/回滚在跑：忙碌期间禁止保存
	var busy = root.getAttribute('data-tk-busy') === '1';

	/* ------------------------------------------------------------ 小工具 */

	function $(sel, ctx) { return (ctx || document).querySelector(sel); }
	function $all(sel, ctx) {
		return Array.prototype.slice.call((ctx || document).querySelectorAll(sel));
	}
	function el(tag, cls, text) {
		var e = document.createElement(tag);
		if (cls) { e.className = cls; }
		if (text !== undefined && text !== null) { e.textContent = String(text); }
		return e;
	}
	function setText(node, text) {
		if (node) { node.textContent = (text === undefined || text === null) ? '' : String(text); }
	}
	/* 频段显示统一走这里：2g → 2.4G, 5g → 5G，其它 → 双频（永远不要出现「2G」） */
	function bandText(b) {
		var s = String(b || '').toLowerCase();
		if (s === '5g') { return '5G'; }
		if (s === '2g' || s === '2.4g' || s === '2') { return '2.4G'; }
		return '双频';
	}

	function clear(node) {
		while (node && node.firstChild) { node.removeChild(node.firstChild); }
	}
	function post(cmd, extra) {
		var body = new URLSearchParams();
		body.set('token', token);
		body.set('cmd', cmd);
		if (extra) {
			Object.keys(extra).forEach(function (k) { body.set(k, extra[k]); });
		}
		return fetch(base + '/action', {
			method: 'POST',
			credentials: 'same-origin',
			cache: 'no-store',
			headers: { 'Content-Type': 'application/x-www-form-urlencoded; charset=UTF-8' },
			body: body.toString()
		}).then(function (r) {
			if (!r.ok) { throw new Error('HTTP ' + r.status); }
			return r.json();
		});
	}
	function getState(what) {
		return fetch(base + '/state?what=' + encodeURIComponent(what) + '&_=' + Date.now(), {
			credentials: 'same-origin',
			cache: 'no-store'
		}).then(function (r) {
			if (!r.ok) { throw new Error('HTTP ' + r.status); }
			return r.json();
		});
	}

	/* ------------------------------------------------------------ 部署遮罩 */

	var overlay = $('#tk-overlay');
	var ovTitle = $('[data-tk-overlay-title]', overlay);
	var ovMsg = $('[data-tk-overlay-msg]', overlay);
	var ovBar = $('[data-tk-progress]', overlay);
	var ovLog = $('[data-tk-log]', overlay);
	var ovReload = $('[data-tk-reload]', overlay);
	var ovClose = $('[data-tk-close]', overlay);

	function openOverlay(title, msg, log) {
		if (!overlay) { return; }
		setText(ovTitle, title);
		setText(ovMsg, msg);
		setText(ovLog, log || '');
		setProgress(0);
		if (ovReload) { ovReload.hidden = true; ovReload.setAttribute('data-tk-goto', ''); }
		overlay.classList.add('is-open');
		overlay.setAttribute('aria-hidden', 'false');
	}
	function closeOverlay() {
		if (!overlay) { return; }
		overlay.classList.remove('is-open');
		overlay.setAttribute('aria-hidden', 'true');
	}
	function setProgress(p) {
		if (!ovBar) { return; }
		p = Math.max(0, Math.min(100, Number(p) || 0));
		ovBar.style.width = p + '%';
	}
	function setReload(href) {
		if (!ovReload) { return; }
		ovReload.hidden = false;
		ovReload.setAttribute('data-tk-goto', href || '');
	}
	if (ovClose) {
		ovClose.addEventListener('click', closeOverlay);
	}
	if (ovReload) {
		ovReload.addEventListener('click', function () {
			var href = ovReload.getAttribute('data-tk-goto');
			if (href) { window.location.href = href; }
			else { window.location.reload(); }
		});
	}
	document.addEventListener('keydown', function (ev) {
		if (ev.key === 'Escape') { closeOverlay(); }
	});

	function failOverlay(title, msg) {
		// 失败时保留 ovLog 里已有的日志（pollJob 刚写入的完整失败输出）：
		// openOverlay 的第三参传 undefined 会把日志清成空串，失败原因就看不到了
		openOverlay(title, msg, ovLog ? ovLog.textContent : '');
		setReload('');
	}

	/*
	 * 轮询后台任务。第一次返回 idle 时再等一轮：
	 * 任务刚提交时 rc/pid 文件可能还没落盘。
	 */
	function pollJob(kind, onDone, onFail) {
		var idleRetry = 0;
		var finished = false;

		function notifyFail(msg) {
			if (finished) { return; }
			finished = true;
			if (typeof onFail === 'function') { onFail({ state: 'failed', msg: msg }); }
		}

		function tick() {
			getState(kind).then(function (j) {
				if (j.state === 'running') {
					setText(ovTitle, kind === 'clean' ? '正在回滚…' : '正在部署…');
					setText(ovMsg, j.msg || '正在执行…');
					setProgress(j.progress || 0);
					setText(ovLog, j.log || '');
					if (ovLog) { ovLog.scrollTop = ovLog.scrollHeight; }
					setTimeout(tick, 1500);
					return;
				}
				if (j.state === 'done' || j.state === 'failed') {
					var ok = j.state === 'done';
					finished = true;
					setProgress(ok ? 100 : (j.progress || 0));
					setText(ovTitle, ok
						? (kind === 'clean' ? '回滚完成' : '部署完成')
						: (kind === 'clean' ? '回滚失败' : '部署失败'));
					setText(ovMsg, j.msg || (ok ? '已完成。' : '请查看下方日志。'));
					setText(ovLog, j.log || '');
					setReload('');
					if (ok) {
						if (typeof onDone === 'function') { onDone(); }
					} else if (typeof onFail === 'function') {
						onFail(j);
					}
					return;
				}
				if (idleRetry < 2) {
					idleRetry += 1;
					openOverlay(kind === 'clean' ? '正在回滚…' : '正在部署…', '任务已提交，等待日志…');
					setTimeout(tick, 1200);
					return;
				}
				setText(ovTitle, '没有正在执行的任务');
				setText(ovMsg, '可以关闭这个窗口，或刷新页面查看最新状态。');
				setReload('');
				notifyFail('没有读取到任务状态');
			}).catch(function () {
				setText(ovTitle, '读取任务状态失败');
				setText(ovMsg, '请刷新页面后重试。');
				setReload('');
				notifyFail('读取任务状态失败');
			});
		}
		tick();
	}

	/* -------------------------------------------------------------- 概览页 */

	function nodeLabel(t) {
		var map = {
			shadowsocks: 'Shadowsocks', vless: 'VLESS', vmess: 'VMess',
			trojan: 'Trojan', socks: 'SOCKS', http: 'HTTP',
			hysteria2: 'Hysteria2', tuic: 'TUIC'
		};
		return map[t] || t || '';
	}

	function classify(it) {
		// err 非空优先强制为「不通」
		if (it.err && String(it.err).trim() !== '') { return ['is-bad', '不通']; }
		if (it.online === true) { return ['is-online', '通']; }
		var note = it.note || '';
		if (/缺少|不存在|netns|veth/.test(note)) { return ['is-off', '未检测']; }
		return ['is-bad', '不通'];
	}

	// 每行「检测」结果缓存（line -> payload）：保证结果恒定显示，不被状态轮询覆盖
	var rowEnvCache = {};

	function cacheLineResult(lineNum, payload) {
		if (lineNum === undefined || lineNum === null || lineNum === '') { return; }
		rowEnvCache[String(lineNum)] = payload;
		checkDuplicateExitIps();
	}

	/* 出口 IP 相同告警：两条线路的出口 IP 相同 = 两个 WiFi 共用一个出口，
	 * 对 TikTok 运营是硬伤。只告警不拦截（用户可能故意共用）。
	 * 数据源：rowEnvCache（每次检测后刷新），横幅插在线路表格上方。 */
	function checkDuplicateExitIps() {
		var old = document.getElementById('tk-dup-exit-bar');
		if (old && old.parentNode) { old.parentNode.removeChild(old); }

		// 出口 IP → 行号列表（只统计检测成功的行）
		var byIp = {};
		Object.keys(rowEnvCache).forEach(function (k) {
			var it = rowEnvCache[k];
			var ip = it && it.exit_ip;
			if (ip && ip !== '' && it.ok !== false) {
				if (!byIp[ip]) { byIp[ip] = []; }
				byIp[ip].push(k);
			}
		});

		var msgs = [];
		Object.keys(byIp).sort().forEach(function (ip) {
			var rows = byIp[ip];
			if (rows.length > 1) {
				rows.sort(function (a, b) { return Number(a) - Number(b); });
				msgs.push('第 ' + rows.join('、') + ' 条出口 IP 相同：' + ip);
			}
		});
		if (!msgs.length) { return; }

		var bar = el('div', 'tk-verdict is-pending');
		bar.id = 'tk-dup-exit-bar';
		bar.style.cssText = 'margin:0.4rem 0;padding:0.45rem 0.7rem;border-radius:5px;'
			+ 'background:#fff3e0;border:1px solid #f0b26a;color:#a05a00;font-size:12.5px;';
		bar.textContent = '⚠ 出口 IP 重复告警：' + msgs.join('；')
			+ '。两个 WiFi 共用一个出口，请更换其中一条线路的节点（仅提示，不阻止部署）。';

		// 插到线路表格卡片头部下方；表格不存在时退回主内容区顶部
		var anchor = document.querySelector('.tk-table-wrap');
		var host = anchor ? (anchor.parentNode || document.getElementById('maincontent') || document.body)
			: (document.getElementById('maincontent') || document.body);
		host.insertBefore(bar, anchor || host.firstChild);
	}

	/* 死节点告警：部署后自动体检的结果（/tmp/tkproxy/nodetest.txt）显示某条线路
	 * 当前绑定的节点不通时提示。这类线路表现为"WiFi 能连上但上不了网"，
	 * 不提示的话客户会误以为是插件坏了。只提示，不阻止部署。 */
	var deadNodePending = false;
	function checkDeadNodes() {
		if (deadNodePending) { return; }
		deadNodePending = true;
		post('node_health').then(function (j) {
			deadNodePending = false;
			var old = document.getElementById('tk-dead-node-bar');
			if (old && old.parentNode) { old.parentNode.removeChild(old); }
			if (!j || j.ok !== true || !j.has_data) { return; }
			if (!j.bound_fail || Number(j.bound_fail) < 1) { return; }
			var names = (j.fails || []).slice(0, 5).map(function (f) {
				return '第' + f.idx + '条 ' + (f.ssid || '') + ' → ' + f.node
					+ (f.reason === 'dns' ? '（DNS 不通）' : '');
			}).join('；');
			var more = (j.fails || []).length > 5 ? ' 等' : '';
			var bar = el('div', 'tk-verdict is-bad');
			bar.id = 'tk-dead-node-bar';
			bar.style.cssText = 'margin:0.4rem 0;padding:0.45rem 0.7rem;border-radius:5px;'
				+ 'background:#fdecea;border:1px solid #e57373;color:#b71c1c;font-size:12.5px;';
			bar.textContent = '⚠ ' + j.bound_fail + ' 条线路绑定的节点体检不通：' + names + more
				+ '。这些 WiFi 连上后会打不开网页，请换绑可用节点（仅提示，不阻止部署）。';
			var anchor = document.querySelector('.tk-table-wrap');
			var host = anchor ? (anchor.parentNode || document.getElementById('maincontent') || document.body)
				: (document.getElementById('maincontent') || document.body);
			host.insertBefore(bar, anchor || host.firstChild);
		}).catch(function () { deadNodePending = false; });
	}

	function findRow(idx, ssid) {
		var tr = root.querySelector('[data-row="' + idx + '"]');
		if (tr) {
			var got = tr.getAttribute('data-ssid') || '';
			if (!ssid || !got || got === ssid) { return tr; }
		}
		if (ssid) {
			var rows = $all('[data-row]', root);
			for (var i = 0; i < rows.length; i += 1) {
				if (rows[i].getAttribute('data-ssid') === ssid) { return rows[i]; }
			}
		}
		return null;
	}

	function renderStatus(items) {
		if (!items || !items.length) { return; }
		items.forEach(function (it, i) {
			var tr = findRow(i + 1, it.ssid);
			if (!tr) { return; }

			var typeCell = $('[data-col="type"]', tr);
			if (typeCell && it.node_type) {
				typeCell.textContent = nodeLabel(it.node_type);
			}

			// 该行已经有「检测」结果：整行按检测结果显示，状态轮询不再覆盖
			// （否则会把用户点出来的通/不通、出口 IP、运营环境徽章冲成未检测）
			var lineKey = String(tr.getAttribute('data-row') || (i + 1));
			if (rowEnvCache[lineKey]) { return; }

			// 没有人工检测过的线路：只提示「资源缺失」，不自动探测、不填出口 IP。
			// 也就是「点哪个查哪个」，没点的行保持未检测。
			var onlineCell = $('[data-col="online"]', tr);
			if (onlineCell) {
				var st = classify(it);
				if (st[0] === 'is-off') {
					while (onlineCell.firstChild) { onlineCell.removeChild(onlineCell.firstChild); }
					var badge = el('span', 'tk-en-btn is-idle', '未检测');
					badge.title = it.note || '';
					onlineCell.appendChild(badge);
					onlineCell.title = it.note || '';
				}
			}
		});
	}

	var statusNote = $('[data-tk-status-note]');
	function setNote(text) { setText(statusNote, text); }

	function finishPendingBadges() {
		$all('[data-col="online"] .tk-badge', root).forEach(function (b) {
			if (b.textContent === '查询中') {
				b.className = 'tk-badge is-off';
				b.textContent = '未检测';
			}
		});
	}

	var statusTimer = null;
	var statusGen = 0;

	// 单一定时器 + generation 计数：
	//   - 重新调度前一定 clearTimeout，避免多条 refreshStatus 链叠加；
	//   - 每次调度递增 generation，过期请求的响应直接丢弃；
	//   - 部署/回滚期间 busy=true，状态轮询整体暂停。
	function cancelStatusPoll() {
		statusGen += 1;
		if (statusTimer) {
			clearTimeout(statusTimer);
			statusTimer = null;
		}
	}

	function scheduleStatus(delay) {
		cancelStatusPoll();
		if (!deployed || busy) { return; }
		var gen = statusGen;
		statusTimer = setTimeout(function () {
			statusTimer = null;
			refreshStatus(gen);
		}, delay);
	}

	function refreshStatus(gen) {
		if (!deployed || busy) { return; }
		if (gen !== undefined && gen !== statusGen) { return; }
		getState('status').then(function (j) {
			if (gen !== undefined && gen !== statusGen) { return; }
			if (busy) { return; }
			if (j.state === 'wait') {
				setNote('部署进行中，状态暂时不可用…');
				scheduleStatus(2500);
				return;
			}
			if (j.state === 'running') {
				if (j.items && j.items.length) { renderStatus(j.items); }
				setNote('正在采集状态…（每条线路单独探测出口 IP，最长约 1–2 分钟）');
				scheduleStatus(2500);
				return;
			}
			if (j.state === 'done') {
				renderStatus(j.items || []);
				finishPendingBadges();
				setNote('状态已更新 · 每 30 秒自动刷新');
				scheduleStatus(30000);
				return;
			}
			if (j.state === 'failed') {
				setNote('状态采集失败：' + (j.msg || '请查看日志') + '（15 秒后重试）');
				scheduleStatus(15000);
				return;
			}
			setNote('尚未部署，状态不可用');
		}).catch(function () {
			if (gen !== undefined && gen !== statusGen) { return; }
			setNote('状态采集请求失败，15 秒后重试');
			scheduleStatus(15000);
		});
	}

	function markDeployed(v) {
		deployed = v;
		var stat = $('.tk-stat-state', root);
		if (stat) { stat.textContent = v ? '已部署' : '未部署'; }
		$all('[data-tk-act="deploy"]', root).forEach(function (db) { db.disabled = false; });
		var rb = $('[data-tk-act="rollback"]', root);
		if (rb) { rb.disabled = !v; }
	}

	/* 执行 + 刷新 双段按钮（业主指定交互）：
	 *   第一次点击：立刻真正执行（不再拦一道确认）
	 *   第二次点击：整页刷新，用来看到执行后的最新状态
	 * 执行成功后按钮文案自动变成「刷新页面」，避免用户不知道该点哪。
	 */
	function armConfirm(btn, opts) {
		opts = opts || {};
		if (btn.__tkRefresh) {           // 第二次：刷新
			window.location.reload();
			return false;
		}
		btn.__tkRefresh = true;
		var doneText = opts.doneText || '刷新页面';
		// 执行通常几百毫秒到几秒；等它跑起来再改文案，别让用户以为没点动
		setTimeout(function () {
			if (!btn.__tkRefresh) { return; }
			btn.textContent = doneText;
			btn.className = (btn.className || '') + ' tk-step-fresh';
			btn.disabled = false;
		}, opts.doneDelay || 900);
		return true;                      // 第一次：直接放行去执行
	}

	/* 执行完把工作区滚到表格（创建/删除后立刻看到结果） */

	function bindDashboard() {
		var deployBtns = $all('[data-tk-act="deploy"]', root);
		var deployBtn = deployBtns[0] || null;
		var rollbackBtn = $('[data-tk-act="rollback"]', root);

		deployBtns.forEach(function (oneBtn) {
			oneBtn.addEventListener('click', function () {
				if (oneBtn.disabled) { return; }
				deployBtns.forEach(function (b) { b.disabled = true; });
				busy = true;
				cancelStatusPoll();
				openOverlay('正在部署…', '正在生成并应用配置，约 10–30 秒；期间 WiFi 可能短暂中断。');
				post('deploy').then(function (j) {
					if (!j.ok) {
						// 「已有部署在运行」不是失败：上一次还在跑，直接跟随它的进度即可
						if (/已有部署在运行|上一次部署/.test(j.msg || '')) {
							openOverlay('上一次部署还在进行…',
								'上一次部署尚未结束（约 2-3 分钟），正在跟随它的进度；完成后会自动刷新页面。');
							pollJob('deploy', function () {
								busy = false;
								markDeployed(true);
								refreshOrReload('部署完成');
								refreshPending();
								setNote('部署完成，正在刷新状态…');
								scheduleStatus(800);
							}, function (j2) {
								busy = false;
								deployBtns.forEach(function (b) { b.disabled = false; });
								failOverlay('部署失败', (j2 && j2.msg) || '请查看日志后重试');
								scheduleStatus(0);
							});
							return;
						}
						busy = false;
						deployBtns.forEach(function (b) { b.disabled = false; });
						failOverlay('部署失败', j.msg || '无法启动部署');
						scheduleStatus(0);
						return;
					}
					pollJob('deploy', function () {
						busy = false;
						markDeployed(true);
						refreshOrReload('部署完成');
						var dflag = $('[data-tk-dirty]');
						if (dflag) { dflag.hidden = true; }
						refreshPending();
						setNote('部署完成，正在刷新状态…');
						scheduleStatus(800);
					}, function (j) {
						busy = false;
						deployBtns.forEach(function (b) { b.disabled = false; });
						// 与「已有部署在运行」分支口径一致：失败要在弹窗里给出完整日志
						failOverlay('部署失败', (j && j.msg) || '请查看日志后重试');
						setNote('部署失败：' + ((j && j.msg) || '请查看日志后重试'));
						scheduleStatus(0);
					});
				}).catch(function () {
					busy = false;
					deployBtns.forEach(function (b) { b.disabled = false; });
					failOverlay('部署失败', '请求失败，请刷新页面后重试。');
					scheduleStatus(0);
				});
			});
		});

		if (rollbackBtn) {
			rollbackBtn.addEventListener('click', function () {
				if (rollbackBtn.disabled) { return; }
				if (!armConfirm(rollbackBtn, {
					armText: '再点一次确认回滚',
					restoreText: '回滚',
					onConfirm: function () { rollbackBtn.disabled = true; }
				})) { return; }
				rollbackBtn.disabled = true;
				busy = true;
				cancelStatusPoll();
				openOverlay('正在回滚…', '正在停止 Xray 并删除本插件写入的配置。');
				post('rollback').then(function (j) {
					if (!j.ok) {
						busy = false;
						rollbackBtn.disabled = false;
						failOverlay('回滚失败', j.msg || '无法启动回滚');
						scheduleStatus(0);
						return;
					}
					pollJob('clean', function () {
						busy = false;
						markDeployed(false);
						setNote('已回滚，线路待重新部署');
						var badges = $all('[data-col="online"] .tk-badge', root);
						badges.forEach(function (b) {
							b.className = 'tk-badge is-pending';
							b.textContent = '待部署';
						});
						var exits = $all('[data-col="exit"]', root);
						exits.forEach(function (c) {
							c.textContent = '—';
							c.className = 'tk-muted';
							c.title = '';
						});
					}, function (j) {
						busy = false;
						rollbackBtn.disabled = false;
						setNote('回滚失败：' + (j.msg || '请查看日志后重试'));
						scheduleStatus(0);
					});
				}).catch(function () {
					busy = false;
					rollbackBtn.disabled = false;
					failOverlay('回滚失败', '请求失败，请刷新页面后重试。');
					scheduleStatus(0);
				});
			});
		}

		/* 用户刷新页面时如果部署/回滚仍在跑，直接接着显示进度 */
		var wasBusy = busy;
		var anyRunning = false;
		var resume = ['deploy', 'clean'].map(function (kind) {
			return getState(kind).then(function (j) {
				if (j.state !== 'running') { return; }
				anyRunning = true;
				busy = true;
				cancelStatusPoll();
				openOverlay(kind === 'clean' ? '正在回滚…' : '正在部署…', j.msg || '');
				pollJob(kind, function () {
					busy = false;
					markDeployed(kind === 'deploy');
					if (kind === 'deploy') { scheduleStatus(800); }
				}, function (j) {
					busy = false;
					var db = $('[data-tk-act="deploy"]', root);
					var rb = $('[data-tk-act="rollback"]', root);
					if (db) { db.disabled = false; }
					if (rb) { rb.disabled = !deployed; }
					// 恢复跟随后失败：弹窗标题改为失败并把完整日志留在弹窗里
					failOverlay(kind === 'clean' ? '回滚失败' : '部署失败',
						(j && j.msg) || '请查看日志后重试');
					setNote('任务失败：' + ((j && j.msg) || '请刷新页面后重试'));
					scheduleStatus(0);
				});
			}).catch(function () { /* 忽略：首屏状态查询失败不影响页面 */ });
		});

		Promise.all(resume).then(function () {
			// 模板渲染时任务还在，但首屏查询时已经结束：重新加载拿到最新状态
			if (wasBusy && !anyRunning) {
				window.location.reload();
				return;
			}
			if (deployed && !busy) { scheduleStatus(0); }
		});
	}

	/* -------------------------------------------------------------- 清单页 */

	function setVerdict(kind, text) {
		var box = $('[data-tk-verdict]', root);
		if (!box) { return; }
		clear(box);
		box.appendChild(el('div', 'tk-verdict-line is-' + kind, text));
	}

	function renderErrors(errors) {
		var box = $('[data-tk-errors]', root);
		if (!box) { return; }
		clear(box);
		if (!errors || !errors.length) { box.hidden = true; return; }
		var ul = el('ul');
		errors.forEach(function (e) {
			var line = Number(e.line) || 0;
			var msg = (line > 0 ? '第 ' + line + ' 行：' : '') + (e.msg || '');
			ul.appendChild(el('li', '', msg));
		});
		box.appendChild(ul);
		box.hidden = false;
	}

	function renderQuota(q) {
		if (!q) { return; }
		var limit = Number(q.limit) || 16;
		[['g2', q.g2], ['g5', q.g5]].forEach(function (pair) {
			var v = Number(pair[1]) || 0;
			var out = $('[data-tk-quota="' + pair[0] + '"]', root);
			if (out) { out.textContent = String(v); }
			var box = $('[data-tk-quota-box="' + pair[0] + '"]', root);
			if (box) { box.classList.toggle('is-full', v >= limit); }
		});
	}

	function renderPreview(rows) {
		var tbody = $('[data-tk-preview-body]', root);
		if (!tbody) { return; }
		clear(tbody);

		if (!rows || !rows.length) {
			var empty = el('tr');
			var td = el('td', 'tk-table-empty', '校验后在这里显示每条线路的网段、端口与节点类型。');
			td.setAttribute('colspan', '7');
			empty.appendChild(td);
			tbody.appendChild(empty);
		} else {
			rows.forEach(function (r) {
				var tr = el('tr');
				tr.setAttribute('data-preview-row', r.idx);

				var c = el('td', 'tk-col-idx');
				c.appendChild(el('span', 'tk-idx', r.idx));
				tr.appendChild(c);

				c = el('td');
				c.appendChild(el('div', 'tk-ssid', r.ssid));
				c.appendChild(el('div', 'tk-slug', r.slug));
				tr.appendChild(c);

				c = el('td');
				c.appendChild(el('span', 'tk-band', r.band_label || bandText(r.band)));
				tr.appendChild(c);

				c = el('td');
				c.appendChild(el('code', 'tk-code', r.subnet || ('10.11.' + r.idx + '.0/24')));
				tr.appendChild(c);

				c = el('td');
				c.appendChild(el('code', 'tk-code', r.port || String(21000 + Number(r.idx))));
				tr.appendChild(c);

				c = el('td', '', (r.node_label || r.node_name || '') || r.node_type || '—');
				tr.appendChild(c);

				c = el('td');
				if (r.error) {
					c.appendChild(el('span', 'tk-badge is-bad', '有问题'));
				} else {
					c.appendChild(el('span', 'tk-badge is-online', '通过'));
				}
				tr.appendChild(c);

				tbody.appendChild(tr);
			});
		}

		var meta = $('[data-tk-preview-meta]', root);
		if (meta) { setText(meta, '共 ' + ((rows && rows.length) || 0) + ' 条'); }
	}

	function renderResult(v) {
		var errors = v.errors || [];
		var q = v.quota || { limit: 16, g2: 0, g5: 0 };
		if (v.ok) {
			setVerdict('ok', '校验通过：' + (v.count || 0) + ' 条线路；2.4G '
				+ (q.g2 || 0) + '/' + (q.limit || 16) + '，5G '
				+ (q.g5 || 0) + '/' + (q.limit || 16) + '。');
		} else {
			setVerdict('bad', '发现 ' + errors.length + ' 个问题，修正后请重新校验。');
		}
		renderErrors(errors);
		if (v.quota) { renderQuota(q); }
		if (v.rows) { renderPreview(v.rows); }
	}

	function bindPorts() {
		var ta = $('#tk-manifest');
		var btnV = $('[data-tk-act="validate"]', root);
		var btnS = $('[data-tk-act="save"]', root);
		if (!ta || !btnV || !btnS) { return; }

		var validated = null;

		if (busy) {
			btnS.disabled = true;
			setVerdict('idle', '部署或回滚正在进行，完成前不能保存。');
			// 任务可能在页面渲染后已结束：核对一次，避免保存按钮永久卡住
			Promise.all([getState('deploy'), getState('clean')]).then(function (res) {
				var running = res.some(function (j) { return j && j.state === 'running'; });
				if (running) { return; }
				busy = false;
				setVerdict('idle', '当前没有进行中的任务。修改内容后请点「校验」。');
			}).catch(function () { /* 保持忙碌态，刷新页面即可恢复 */ });
		}

		ta.addEventListener('input', function () {
			validated = null;
			btnS.disabled = true;
			setVerdict('idle', '内容已修改，请重新校验。');
		});

		btnV.addEventListener('click', function () {
			if (btnV.disabled) { return; }
			// 快照本次要校验的文本；响应回来时内容若已变，结果作废
			var snapshot = ta.value;
			btnV.disabled = true;
			setVerdict('idle', '正在校验…');
			post('validate', { text: snapshot }).then(function (v) {
				btnV.disabled = false;
				if (ta.value !== snapshot) {
					validated = null;
					btnS.disabled = true;
					setVerdict('idle', '内容在校验期间被修改，请重新校验。');
					return;
				}
				validated = snapshot;
				renderResult(v);
				btnS.disabled = busy || !v.ok;
			}).catch(function () {
				btnV.disabled = false;
				setVerdict('bad', '校验请求失败，请刷新页面后重试。');
			});
		});

		btnS.addEventListener('click', function () {
			if (btnS.disabled || busy) { return; }
			if (validated === null || validated !== ta.value) { return; }
			btnS.disabled = true;
			setVerdict('idle', '已通过校验，正在保存并启动部署…');
			post('save', { text: ta.value }).then(function (j) {
				if (!j.ok) {
					renderResult(j);
					// 失败时恢复按钮（忙碌期间保持禁用），让用户修正后重试
					btnS.disabled = busy;
					setVerdict('bad', (j.msg || '保存失败') + ' 请检查下方问题后重试。');
					return;
				}
				window.location.href = base + '/dashboard';
			}).catch(function () {
				btnS.disabled = busy;
				setVerdict('bad', '保存请求失败，请刷新页面后重试。');
			});
		});
	}


	/* ------------------------------------------------------------ 批量创建 */
	function bindBatch() {
		var box = $('[data-tk-batch]', root);
		if (!box) { return; }
		var bCount = $('#tk-b-count'), bPrefix = $('#tk-b-prefix'), bStart = $('#tk-b-start');
		var bPass = $('#tk-b-password'), bMode = $('#tk-b-mode');
		var b2 = $('#tk-b-2g'), b5 = $('#tk-b-5g');
		var w2 = $('#tk-b-2g-wrap'), w5 = $('#tk-b-5g-wrap');
		var btnP = $('[data-tk-act="batch-preview"]', box);
		var btnG = $('[data-tk-act="batch-generate"]', box);
		var verdict = $('[data-tk-batch-verdict]', box);
		if (!bCount || !btnP || !btnG || !verdict) { return; }
		var previewOk = false;
		var inputs = [bCount, bPrefix, bStart, bPass, b2, b5];

		function params() {
			return {
				count: bCount.value,
				prefix: bPrefix.value,
				start_seq: bStart.value,
				password: bPass.value,
				mode: bMode ? bMode.value : 'auto',
				count_2g: b2 ? b2.value : '0',
				count_5g: b5 ? b5.value : '0'
			};
		}
		function say(cls, text) {
			verdict.textContent = '';
			var d = document.createElement('div');
			d.className = 'tk-verdict-line ' + cls;
			d.textContent = text;
			verdict.appendChild(d);
		}
		function invalidate() {
			previewOk = false;
			btnG.disabled = true;
		}

		if (bMode) {
			bMode.addEventListener('change', function () {
				var manual = bMode.value === 'manual';
				if (w2) { w2.hidden = !manual; }
				if (w5) { w5.hidden = !manual; }
				invalidate();
			});
		}
		inputs.forEach(function (el) {
			if (el) { el.addEventListener('input', invalidate); }
		});

		btnP.addEventListener('click', function () {
			if (btnP.disabled) { return; }
			btnP.disabled = true;
			say('is-idle', '正在计算名额…');
			post('batch_preview', params()).then(function (v) {
				btnP.disabled = false;
				if (!v.ok) {
					invalidate();
					say('is-bad', (v.errors || []).join('；') || '预览失败');
					return;
				}
				previewOk = true;
				btnG.disabled = busy;
				say('is-online', '将创建 ' + v.need_2g + ' 条 2.4G + ' + v.need_5g +
					' 条 5G；创建后 2.4G=' + v.final_2g + '、5G=' + v.final_5g + '（单射频上限 16，已含主 WiFi）');
			}).catch(function () {
				btnP.disabled = false;
				invalidate();
				say('is-bad', '预览请求失败，请刷新页面重试。');
			});
		});

		btnG.addEventListener('click', function () {
			if (!previewOk || btnG.disabled) { return; }
			btnG.disabled = true;
			say('is-idle', '正在生成并保存清单…');
			post('batch_generate', params()).then(function (j) {
				if (!j.ok) {
					btnG.disabled = false;
					say('is-bad', j.msg || '生成失败');
					return;
				}
				say('is-online', j.msg || '已生成');
				setTimeout(function () { window.location.reload(); }, 1200);
			}).catch(function () {
				btnG.disabled = false;
				say('is-bad', '生成请求失败，请刷新页面重试。');
			});
		});
	}

	/* -------------------------------------------------------------- 节点池页 */

	function bindNodes() {
		var importBtn = $('[data-tk-act="import-nodes"]', root);
		var fetchBtn = $('[data-tk-act="fetch-sub"]', root);
		var importText = $('#tk-import-text');
		var subUrl = $('#tk-sub-url');

		if (fetchBtn) {
			fetchBtn.addEventListener('click', function () {
				if (fetchBtn.disabled) { return; }
				var url = subUrl ? subUrl.value.replace(/^\s+|\s+$/g, '') : '';
				if (!url) {
					setVerdict('bad', '订阅 URL 不能为空');
					return;
				}
				fetchBtn.disabled = true;
				setVerdict('idle', '正在拉取订阅…');
				post('fetch_subscription', { url: url }).then(function (j) {
					fetchBtn.disabled = false;
					if (!j.ok) {
						setVerdict('bad', j.msg || '拉取失败');
						return;
					}
					if (importText) { importText.value = j.text || ''; }
					setVerdict('ok', '拉取成功，已填入下方文本框。检查后点「导入」。');
				}).catch(function () {
					fetchBtn.disabled = false;
					setVerdict('bad', '请求失败，请检查 URL 和网络后重试。');
				});
			});
		}

		if (importBtn && importText) {
			importBtn.addEventListener('click', function () {
				if (importBtn.disabled) { return; }
				var text = importText.value;
				if (!text || text.replace(/^\s+|\s+$/g, '') === '') {
					setVerdict('bad', '请粘贴至少一条节点链接');
					return;
				}
				importBtn.disabled = true;
				setVerdict('idle', '正在导入…');
				post('import_nodes', { text: text }).then(function (j) {
					importBtn.disabled = false;
					if (!j.ok) {
						setVerdict('bad', j.msg || '导入失败');
						if (j.bad_lines && j.bad_lines.length > 0) {
							var box = $('[data-tk-errors]', root);
							if (box) {
								clear(box);
								var ul = el('ul');
								j.bad_lines.forEach(function (b) {
									var txt = '第 ' + b.line + ' 行：' + (b.text || '格式错误');
									if (b.reason) { txt += '  →  ' + b.reason; }
									var li = el('li', '', txt);
									if (b.reason && b.reason.indexOf('不支持') >= 0) {
										li.style.color = '#d32f2f';
										li.style.fontWeight = '600';
									}
									ul.appendChild(li);
								});
								box.appendChild(ul);
								box.hidden = false;
							}
						}
						return;
					}
					setVerdict('ok', j.msg || '导入成功');
					renderErrors([]);
					setTimeout(function () { window.location.reload(); }, 800);
				}).catch(function () {
					importBtn.disabled = false;
					setVerdict('bad', '请求失败，请刷新页面后重试。');
				});
			});
		}

		/* 清空全部节点（两段式确认） */
		var btnClearNodes = $('[data-tk-act="nodes-clear"]', root);
		if (btnClearNodes) {
			btnClearNodes.addEventListener('click', function () {
				if (!armConfirm(btnClearNodes, {
					armText: '再点一次清空全部节点',
					restoreText: '清空全部节点',
					onConfirm: function () { /* 继续 */ }
				})) { return; }
				btnClearNodes.disabled = true;
				postBind('nodes_clear').then(function (r) {
					btnClearNodes.disabled = false;
					if (!r || r.ok === false) {
						window.alert((r && r.msg) || '清空失败');
						return;
					}
					window.location.reload();
				}).catch(function () { btnClearNodes.disabled = false; });
			});
		}

		var deleteBtns = $all('[data-tk-act="delete-node"]', root);
		deleteBtns.forEach(function (btn) {
			btn.addEventListener('click', function () {
				if (btn.disabled) { return; }
				var name = btn.getAttribute('data-tk-name');
				if (!name) { return; }
				if (!armConfirm(btn, {
					armText: '再点一次确认删除',
					restoreText: '删除',
					onConfirm: function () { /* 继续执行下面的删除 */ }
				})) { return; }
				btn.disabled = true;
				post('delete_node', { name: name }).then(function (j) {
					if (!j.ok) {
						btn.disabled = false;
						alert(j.msg || '删除失败');
						return;
					}
					/* 主表格行与 SOCKS5 卡片行各删各的（两个表格可能有同名行） */
					var row = root.querySelector('[data-node-name="' + name + '"]');
					if (row && row.parentNode) { row.parentNode.removeChild(row); }
					row = root.querySelector('[data-socks5-name="' + name + '"]');
					if (row && row.parentNode) { row.parentNode.removeChild(row); }
					/* 顶部「共 N 个」是服务端渲染的，删完就地更新，避免显示与实际不一致 */
					var meta = $('.tk-card-meta', root);
					var bodyRows = $all('tbody tr', root).filter(function (tr) {
						return tr.querySelector('[data-tk-act="delete-node"]');
					});
					if (meta && /个/.test(meta.textContent)) {
						meta.textContent = '共 ' + bodyRows.length + ' 个';
					}
					var empty = $('[data-tk-socks5-empty]', root);
					if (empty && bodyRows.length === 0) { empty.style.display = ''; }
				}).catch(function () {
					btn.disabled = false;
					alert('请求失败，请刷新页面后重试。');
				});
			});
		});
	}

	/* ------------------------------------------------------ SOCKS5 页面（t_299f5f62，原 t_309a22f3 卡片迁出为独立分类页） */

	function bindSocks5() {
		/* 独立页把标记打在页面根容器上（root 自身），querySelector 搜不到自己，需回退一次 */
		var card = $('[data-tk-socks5-card]', root)
			|| (root && root.hasAttribute && root.hasAttribute('data-tk-socks5-card') ? root : null);
		if (!card) { return; }
		var nameEl = $('#tk-socks5-name');
		var addrEl = $('#tk-socks5-addr');
		var frontEl = $('#tk-socks5-front');
		var addBtn = $('[data-tk-act="socks5-add"]', card);

		function say(kind, text) {
			var box = $('[data-tk-socks5-verdict]', card);
			if (!box) { return; }
			clear(box);
			box.appendChild(el('div', 'tk-verdict-line is-' + kind, text));
		}

		if (addBtn && addrEl) {
			addBtn.addEventListener('click', function () {
				if (addBtn.disabled) { return; }
				var addr = addrEl.value.replace(/^\s+|\s+$/g, '');
				if (!addr) {
					say('bad', '请填写 SOCKS5 地址');
					return;
				}
				/* 复用现有 import_nodes 单行导入：名称|链接；后端 parse_node_entry
				 * 已支持 socks5:// 与四段写法，前端只负责把前置拼成 ?front= */
				var link = addr;
				if (!/:\/\//.test(link)) { link = 'socks5://' + link; }
				var front = frontEl ? frontEl.value : '';
				if (front) { link += '?front=' + encodeURIComponent(front); }
				var name = nameEl ? nameEl.value.replace(/^\s+|\s+$/g, '') : '';
				var entry = name ? (name + '|' + link) : link;

				addBtn.disabled = true;
				say('idle', '正在添加…');
				post('import_nodes', { text: entry }).then(function (j) {
					addBtn.disabled = false;
					if (!j.ok) {
						say('bad', j.msg || '添加失败');
						return;
					}
					say('ok', '已加入节点池，去绑定页绑定到 WiFi');
					if (nameEl) { nameEl.value = ''; }
					addrEl.value = '';
					if (frontEl) { frontEl.value = ''; }
					/* 删除按钮走 bindNodes 的委托，这里刷新让新行带占用检查 */
					setTimeout(function () { window.location.reload(); }, 1200);
				}).catch(function () {
					addBtn.disabled = false;
					say('bad', '请求失败，请刷新页面后重试。');
				});
			});
		}
	}

	/* -------------------------------------------------------------- 编辑页 */

	function bindEdit() {
		var btn = $('[data-tk-act="save-edit"]', root);
		if (!btn) { return; }
		var ssidEl = $('#tk-ssid');
		var bandEl = $('#tk-band');
		var linkEl = $('#tk-link');
		var nodeSelect = $('#tk-node-select');
		var modePool = $('#tk-mode-pool');
		var modeDirect = $('#tk-mode-direct');

		// 节点选择模式切换
		if (modePool && modeDirect && nodeSelect && linkEl) {
			function updateMode() {
				if (modePool.checked) {
					nodeSelect.style.display = '';
					linkEl.style.display = 'none';
				} else {
					nodeSelect.style.display = 'none';
					linkEl.style.display = '';
				}
			}
			modePool.addEventListener('change', updateMode);
			modeDirect.addEventListener('change', updateMode);
		}

		if (busy) {
			btn.disabled = true;
			setVerdict('idle', '部署或回滚正在进行，完成前不能保存。');
			Promise.all([getState('deploy'), getState('clean')]).then(function (res) {
				var running = res.some(function (j) { return j && j.state === 'running'; });
				if (running) { return; }
				busy = false;
				btn.disabled = false;
				setVerdict('idle', '当前没有进行中的任务，可以保存。');
			}).catch(function () { /* 保持忙碌态，刷新页面即可恢复 */ });
		}

		btn.addEventListener('click', function () {
			if (btn.disabled || busy) { return; }
			if (!ssidEl || !bandEl) { return; }
			var ssid = ssidEl.value.replace(/^\s+|\s+$/g, '');
			var link = '';
			if (modePool && modePool.checked && nodeSelect) {
				link = nodeSelect.value.replace(/^\s+|\s+$/g, '');
			} else if (linkEl) {
				link = linkEl.value.replace(/^\s+|\s+$/g, '');
			}
			if (!ssid) {
				setVerdict('bad', 'SSID 不能为空。');
				return;
			}
			if (!link) {
				setVerdict('bad', '节点链接不能为空。');
				return;
			}
			btn.disabled = true;
			busy = true;
			cancelStatusPoll();
			openOverlay('正在保存…', '正在写入清单，随后重建这条线路。');
			post('save_edit', {
				i: root.getAttribute('data-tk-idx') || '',
				ssid: ssid,
				band: bandEl.value,
				link: link
			}).then(function (j) {
				if (!j.ok) {
					busy = false;
					btn.disabled = false;
					closeOverlay();
					setVerdict('bad', (j.msg || '保存失败') + ' 请检查下方问题。');
					renderErrors(j.errors || []);
					return;
				}
				setVerdict('idle', j.msg || '保存成功，正在重建。');
				renderErrors([]);
				pollJob('deploy', function () {
					busy = false;
					if (ovReload) {
						ovReload.setAttribute('data-tk-goto', base + '/dashboard');
						ovReload.textContent = '回到概览';
					}
				}, function (j) {
					busy = false;
					btn.disabled = false;
					setVerdict('bad', '重建失败：' + (j.msg || '请查看日志后重试'));
					if (ovReload) {
						ovReload.setAttribute('data-tk-goto', base + '/dashboard');
						ovReload.textContent = '回到概览';
					}
				});
			}).catch(function () {
				busy = false;
				btn.disabled = false;
				closeOverlay();
				setVerdict('bad', '保存请求失败，请刷新页面后重试。');
			});
		});
	}

	/* ------------------------------------------------------------ purity 页面 */

	function bindPurity() {
		var resultBody = $('[data-tk-result-body]');
		var checkNote = $('[data-tk-check-note]');
		var statsContainer = $('[data-tk-stats]');
		var runCheckBtn = $('[data-tk-act="run-check"]');
		var rulesForm = $('[data-tk-rules-form]');

		function renderResults(items, summary) {
			clear(resultBody);
			if (!items || items.length === 0) {
				var tr = el('tr');
				var td = el('td', '', '暂无体检数据');
				td.setAttribute('colspan', '9');
				td.style.textAlign = 'center';
				td.style.padding = '3rem 1rem';
				td.style.color = '#999';
				tr.appendChild(td);
				resultBody.appendChild(tr);
				return;
			}

			items.forEach(function (it) {
				var tr = el('tr');
				var verdictClass = '';
				var verdictText = '未知';
				if (it.verdict === 'pass') {
					verdictClass = 'is-pass';
					verdictText = '✓ 可用';
				} else if (it.verdict === 'risk') {
					verdictClass = 'is-risk';
					verdictText = '⚠ 有风险';
				} else if (it.verdict === 'fail') {
					verdictClass = 'is-fail';
					verdictText = '✗ 不可用';
				} else if (it.verdict === 'unknown') {
					verdictText = '未知';
				}

				var cells = [
					el('td', '', it.ssid || ''),
					el('td', '', bandText(it.band)),
					el('td', '', it.exit_ip || '—'),
					el('td', '', it.country || '—'),
					el('td', '', it.is_datacenter ? '是' : '否'),
					el('td', '', it.dns_consistent ? '是' : '否'),
					el('td', '', it.ipv6_leak ? '泄漏' : '正常'),
					el('td', 'tk-verdict ' + verdictClass, verdictText),
					el('td', '', it.reasons || '—')
				];
				cells.forEach(function (c) { tr.appendChild(c); });
				resultBody.appendChild(tr);
			});

			// 更新统计卡片
			if (summary && statsContainer) {
				setText($('[data-tk-stat="pass"]', statsContainer), summary.pass || 0);
				setText($('[data-tk-stat="risk"]', statsContainer), summary.risk || 0);
				setText($('[data-tk-stat="fail"]', statsContainer), summary.fail || 0);
				setText($('[data-tk-stat="dup"]', statsContainer), summary.dup_ip_count || 0);
			}

			if (checkNote) {
				setText(checkNote, '体检完成，共 ' + items.length + ' 条线路');
			}
		}

		if (runCheckBtn) {
			runCheckBtn.addEventListener('click', function () {
				if (runCheckBtn.disabled) { return; }
				runCheckBtn.disabled = true;
				setText(checkNote, '体检中，请稍候…');

				post('run_purity_check').then(function (j) {
					runCheckBtn.disabled = false;
					if (!j.ok) {
						setText(checkNote, '体检失败：' + (j.msg || '未知错误'));
						return;
					}
					renderResults(j.items || [], j.summary || {});
				}).catch(function (err) {
					runCheckBtn.disabled = false;
					setText(checkNote, '体检请求失败：' + err.message);
				});
			});
		}

		if (rulesForm) {
			rulesForm.addEventListener('submit', function (ev) {
				ev.preventDefault();
				var formData = new FormData(rulesForm);
				var params = {};
				formData.forEach(function (v, k) { params[k] = v; });

				// 复选框未勾选时不在 FormData 里，需要手动补 0
				['require_residential', 'require_unique_ip', 'require_dns_consistent', 'block_ipv6_leak'].forEach(function (k) {
					if (!params[k]) { params[k] = '0'; }
				});

				post('save_purity_rules', params).then(function (j) {
					if (j.ok) {
						alert(j.msg || '规则已保存');
					} else {
						alert(j.msg || '保存失败');
					}
				}).catch(function () {
					alert('保存请求失败');
				});
			});
		}
	}

	/* ---------------------------------------------------------------- 启动 */


	/* ------------------------------------------------------- 首页工作台（对齐老插件） */
	function postBind(cmd, extra) {
		var body = new URLSearchParams();
		body.set('token', token);
		body.set('cmd', cmd);
		if (extra) {
			Object.keys(extra).forEach(function (k) { body.set(k, extra[k]); });
		}
		return fetch(base + '/bind', {
			method: 'POST',
			credentials: 'same-origin',
			cache: 'no-store',
			headers: { 'Content-Type': 'application/x-www-form-urlencoded; charset=UTF-8' },
			body: body.toString()
		}).then(function (r) {
			if (!r.ok) { throw new Error('HTTP ' + r.status); }
			return r.json();
		});
	}

	/* 重绘表格（导入/创建成功后不整页reload，只重绘） */
	function reloadTable() {
		return postBind('bind_rows').then(function (r) {
			if (!r || !r.ok || !r.rows) { throw new Error('无法获取行数据'); }
			try {
				renderTable(r.rows, r.pool || []);
				updateStats(r.rows);
			} catch (e) {
				console.error('tkproxy: 表格重绘失败', e);
				throw e;
			}
			return r;
		});
	}

	/* 表格刷新失败时的兜底：自动整页刷新，用户不用自己按 F5 */
	function refreshOrReload(where) {
		return reloadTable().catch(function (e) {
			console.warn('tkproxy: ' + (where || '') + ' 后表格刷新失败，自动整页刷新', e);
			setTimeout(function () { window.location.reload(); }, 400);
		});
	}

	/* 让页面滚到表格，创建/删除后立刻看到结果 */
	function scrollToTable() {
		var tb = $('#tk-bind-tbody');
		if (!tb) { return; }
		var sec = tb.closest ? tb.closest('section') : null;
		if (sec && sec.scrollIntoView) {
			try { sec.scrollIntoView({ behavior: 'smooth', block: 'start' }); } catch (e) { /* 老浏览器忽略 */ }
		}
	}

	function updateStats(rows) {
		var en = 0, bound = 0, g2 = 0, g5 = 0;
		rows.forEach(function (r) {
			if (r.enabled !== false) {
				en += 1;
				// 名额口径与后端一致：2g/both 占 2.4G，5g/both 占 5G（禁用行不占名额）
				var b = String(r.band || '').toLowerCase();
				if (b === '2g' || b === 'both') { g2 += 1; }
				if (b === '5g' || b === 'both') { g5 += 1; }
			}
			if (r.node_name && r.node_name !== '') { bound += 1; }
		});
		var eEl = $('[data-tk-count-en]');
		var bEl = $('[data-tk-count-bound]');
		if (eEl) { eEl.textContent = String(en); }
		if (bEl) { bEl.textContent = String(bound); }
		// 摘要卡片与「共 N 条」跟着重绘刷新，不再停留在首屏值
		var total = rows.length;
		var lim = parseInt(root.getAttribute('data-tk-limit') || '16', 10) || 16;
		setText($('[data-tk-stat-total]'), total);
		setText($('[data-tk-stat-total-meta]'), total);
		setText($('[data-tk-stat-g2]'), g2);
		setText($('[data-tk-stat-g5]'), g5);
		// 分母钩子两处都有（2.4G / 5G 卡片各一），setText 会全部刷新
		$all('[data-tk-stat-limit]').forEach(function (n) { n.textContent = String(lim); });
		// 名额满时标黄（与首屏渲染口径一致）
		var c2 = $('[data-tk-quota-card="g2"]');
		if (c2) { c2.classList.toggle('is-warn', g2 >= lim); }
		var c5 = $('[data-tk-quota-card="g5"]');
		if (c5) { c5.classList.toggle('is-warn', g5 >= lim); }
	}

	function renderTable(rows, pool) {
		var tbody = $('#tk-bind-tbody');
		if (!tbody) { return; }
		clear(tbody);

		// 节点占用统计
		var usage = {};
		rows.forEach(function (r) {
			var n = r.node_name || '';
			if (n) { usage[n] = (usage[n] || 0) + 1; }
		});

		rows.forEach(function (r) {
			var tr = el('tr');
			tr.setAttribute('data-row', r.idx);
			tr.setAttribute('data-ssid', r.ssid);
			if (r.enabled === false) { tr.style.opacity = '.55'; }

			// #
			var c = el('td', 'tk-col-idx');
			c.appendChild(el('span', 'tk-idx', r.idx));
			tr.appendChild(c);

			// SSID
			c = el('td');
			c.appendChild(el('div', 'tk-ssid', r.ssid));
			c.appendChild(el('div', 'tk-slug', r.slug));
			tr.appendChild(c);

			// 频段
			c = el('td');
			c.appendChild(el('span', 'tk-band', r.band_label || bandText(r.band)));
			tr.appendChild(c);

			// 网段
			c = el('td');
			c.appendChild(el('code', 'tk-code', r.subnet || ('10.11.' + r.idx + '.0/24')));
			tr.appendChild(c);

			// 端口
			c = el('td');
			c.appendChild(el('code', 'tk-code', r.port || String(21000 + Number(r.idx))));
			tr.appendChild(c);

			// 绑定节点
			c = el('td');
			if (pool && pool.length > 0) {
				var sel = document.createElement('select');
				sel.className = 'cbi-input-select tk-node-sel';
				sel.setAttribute('data-bind-select', r.idx);
				var opt = document.createElement('option');
				opt.value = '';
				opt.textContent = '— 未绑定 —';
				sel.appendChild(opt);
				pool.forEach(function (n) {
					var o = document.createElement('option');
					o.value = n.name;
					o.textContent = n.name;
					if (r.node_name === n.name) { o.selected = true; }
					sel.appendChild(o);
				});
				c.appendChild(sel);

				var slug = el('div', 'tk-slug');
				if (r.node_name && r.node_name !== '') {
					var txt = '节点池';
					if (usage[r.node_name] > 1) {
						txt += ' · 与其它 ' + (usage[r.node_name] - 1) + ' 行共用（仅提示）';
					}
					slug.textContent = txt;
				} else {
					slug.textContent = '未绑定';
				}
				c.appendChild(slug);
			} else {
				if (r.node_name && r.node_name !== '') {
					c.appendChild(el('div', 'tk-ssid', r.node_name));
					c.appendChild(el('div', 'tk-slug', '节点池'));
				} else {
					c.appendChild(el('div', 'tk-ssid', r.node_server || '—'));
					c.appendChild(el('div', 'tk-slug', '直连链接'));
				}
			}
			tr.appendChild(c);

			// 启用/禁用：两态按钮（禁用=红色，不用勾选框）
			c = el('td', 'tk-col-en');
			var on0 = (r.enabled !== false);
			var enBtn = el('button',
				'tk-en-btn ' + (on0 ? 'is-on' : 'is-off'),
				on0 ? '已启用' : '已禁止');
			enBtn.type = 'button';
			enBtn.setAttribute('data-bind-toggle', r.idx);
			enBtn.setAttribute('data-enabled', on0 ? '1' : '0');
			enBtn.title = '点击切换：已启用 / 已禁止';
			c.appendChild(enBtn);
			tr.appendChild(c);

			// 状态
			c = el('td', 'tk-muted', '未检测');
			c.setAttribute('data-col', 'online');
			tr.appendChild(c);

			// 运营环境
			c = el('td', 'tk-muted', '未检测');
			c.setAttribute('data-col', 'env');
			tr.appendChild(c);

			// 出口 IP
			c = el('td', 'tk-muted', '未检测');
			c.setAttribute('data-col', 'exit');
			tr.appendChild(c);

			// 操作
			c = el('td', 'tk-col-act');
			var btnCheck = el('button', 'cbi-button tk-btn-sm tk-btn-check', '检测');
			btnCheck.type = 'button';
			btnCheck.setAttribute('data-line', r.idx);
			c.appendChild(btnCheck);
			var btnEdit = el('button', 'cbi-button tk-btn-sm tk-btn-edit', '编辑');
			btnEdit.type = 'button';
			btnEdit.setAttribute('data-line-edit', r.idx);
			btnEdit.setAttribute('data-ssid-name', r.ssid || '');
			btnEdit.setAttribute('data-band-name', r.band || '2g');
			btnEdit.setAttribute('data-enabled-flag', (r.enabled === false) ? '0' : '1');
			c.appendChild(btnEdit);
			// 重绘的行也要带「保存并部署」：否则仅保存/换节点等触发表格重绘后行内按钮消失
			var btnApply = el('button', 'cbi-button tk-btn-sm cbi-button-apply', '保存并部署');
			btnApply.type = 'button';
			btnApply.setAttribute('data-line-deploy', r.idx);
			btnApply.title = '只重建这一条线路（约 10-30 秒），不会动其它 SSID';
			c.appendChild(btnApply);
			var btnDel = el('button', 'cbi-button tk-btn-sm', '删除');
			btnDel.type = 'button';
			btnDel.setAttribute('data-bind-del', r.idx);
			c.appendChild(btnDel);
			tr.appendChild(c);

			tbody.appendChild(tr);
		});

		// 重新绑定事件
		bindTableEvents();
		restorePurityState();
		refreshPending();
	}

	/* 「已有改动 N 条，请点击保存并部署」顶部提醒条 */
	var pendingBar = null;
	function ensurePendingBar() {
		if (pendingBar && pendingBar.parentNode) { return pendingBar; }
		pendingBar = el('div');
		pendingBar.id = 'tk-pending-bar';
		pendingBar.style.cssText = 'display:none;margin:0 0.6rem 0 0;padding:0.28rem 0.6rem;border-radius:5px;'
			+ 'background:#fff8e6;border:1px solid #f0dca8;color:#b26a00;font-size:12.5px;'
			+ 'align-items:center;gap:0.5rem;vertical-align:middle;white-space:nowrap;';
		// 贴着「保存并部署」按钮放，一起看更显眼
		var dbs = document.querySelectorAll('[data-tk-act="deploy"]');
		if (dbs.length && dbs[0].parentNode) {
			dbs[0].parentNode.insertBefore(pendingBar, dbs[0]);
		} else {
			var host = document.getElementById('maincontent') || document.body;
			host.insertBefore(pendingBar, host.firstChild);
		}
		var txt = el('span', null, '');
		txt.id = 'tk-pending-text';
		txt.style.flex = '1';
		pendingBar.appendChild(txt);
		host.insertBefore(pendingBar, host.firstChild);
		return pendingBar;
	}
	function refreshPending() {
		post('pending').then(function (j) {
			if (!j || !j.ok) { return; }
			var bar = ensurePendingBar();
			var txt = document.getElementById('tk-pending-text');
			if (j.pending > 0) {
				txt.textContent = '⚠ 已有改动 ' + j.pending + ' 条，请点「保存并部署」';
				bar.title = '新增 ' + (j.added || 0) + ' / 修改 ' + (j.changed || 0)
					+ ' / 删除 ' + (j.removed || 0) + '（相对上次部署）';
				bar.style.display = 'inline-flex';
			} else {
				bar.style.display = 'none';
			}
			// 老的『有改动未部署』小标签与新提醒条重复，统一由提醒条表达
			var dflag = document.querySelector('[data-tk-dirty]');
			if (dflag) { dflag.hidden = true; }
		}).catch(function () { /* 忽略：拿不到就不提示 */ });
	}

	/* 用服务端落盘的检测结果恢复表格：刷新/重渲染后仍显示，徽章可点开弹窗 */
	function restorePurityState() {
		post('purity_state').then(function (j) {
			if (!j || !j.ok || !j.items) { return; }
			Object.keys(j.items).forEach(function (k) {
				var d = j.items[k];
				var tr = document.querySelector('tr[data-row="' + k + '"]');
				if (!tr || !d) { return; }
				if (rowEnvCache[k]) { return; }
				var okk = !!(d.exit_ip && d.exit_ip !== '');
				var onlineCell = tr.querySelector('[data-col="online"]');
				if (onlineCell) {
					onlineCell.textContent = '';
					var b = el('span', 'tk-en-btn ' + (okk ? 'is-on' : 'is-off'), okk ? '通' : '不通');
					b.title = d.env_miss || '';
					onlineCell.appendChild(b);
				}
				var envCell = tr.querySelector('[data-col="env"]');
				if (envCell) {
					envCell.textContent = '';
					var lvl = d.env_level || (d.verdict === 'pass' ? 'ok' : (d.verdict === 'risk' ? 'warn' : 'err'));
					var cls = (lvl === 'ok') ? 'is-on' : ((lvl === 'warn') ? 'is-warn' : 'is-off');
					var txt = (lvl === 'ok') ? '可用' : ((lvl === 'warn') ? '有风险' : '不可用');
					var eb = el('span', 'tk-en-btn ' + cls, txt);
					eb.style.cursor = 'pointer';
					eb.title = '点击查看线路体检（' + (d.summary || '') + '）';
					eb.addEventListener('click', function (ev) {
						ev.stopPropagation();
						d.ssid = tr.getAttribute('data-ssid') || ('TK-' + k);
						d.line = k;
						d.lineNum = k;
						if (typeof showEnvDetail === 'function') { showEnvDetail(d); }
					});
					envCell.appendChild(eb);
				}
				var exitCell = tr.querySelector('[data-col="exit"]');
				if (exitCell) {
					if (okk) {
						exitCell.textContent = (d.country ? d.country + ' ' : '') + d.exit_ip;
						exitCell.className = 'tk-mono';
					} else {
						exitCell.textContent = d.env_miss || '检测失败';
						exitCell.className = 'tk-muted';
					}
				}
				rowEnvCache[String(k)] = { ok: okk, status: okk ? 'ok' : 'fail', exit_ip: d.exit_ip || '' };
			});
			checkDuplicateExitIps();
			checkDeadNodes();
		}).catch(function () { /* 忽略：读不到就不恢复 */ });
	}

	/* 单条线路部署：只重建这一条，失败也只影响这一行 */
	function deployOneLine(btn) {
		var idx = btn.getAttribute('data-line-deploy');
		var oldTxt = btn.textContent;
		btn.disabled = true;
		btn.textContent = '部署中…';
		function restore() { btn.disabled = false; btn.textContent = oldTxt; }
		post('deploy_line', { idx: idx }).then(function (j) {
			if (!j || !j.ok) {
				restore();
				var m = (j && j.msg) || '无法启动部署';
				if (/还在进行|已有部署在运行/.test(m)) {
					setNote('上一次部署还在进行，等它结束再试');
				} else {
					window.alert('部署失败：' + m);
				}
				return;
			}
			openOverlay('正在部署第 ' + idx + ' 条…', '只重建这一条线路，其它 SSID 不受影响；约 10-30 秒。');
			pollJob('deploy', function () {
				restore();
				setNote('第 ' + idx + ' 条已部署完成');
				refreshPending();
				restorePurityState();
			}, function (j2) {
				restore();
				failOverlay('部署失败', (j2 && j2.msg) || '请查看日志');
			});
		}).catch(function (e) {
			restore();
			window.alert('部署请求失败：' + ((e && e.message) || e));
		});
	}

	/* 触发「保存并部署」：直接复用概览页那个部署按钮的完整流程 */
	function postDeploy() {
		var db = document.querySelector('[data-tk-act="deploy"]');
		if (typeof busy !== 'undefined' && busy) {
			setNote('上一次部署还在进行中，请稍候…');
			return false;
		}
		if (db && !db.disabled) {
			db.click();
			// 部署期间每 3 秒刷一次提醒条，部署完自动消失（不用手动刷新页面）
			var tries = 0;
			var t = setInterval(function () {
				tries += 1;
				refreshPending();
				if (tries >= 20) { clearInterval(t); }
			}, 3000);
			return true;
		}
		return false;
	}

	/* 单行编辑弹窗：改 SSID 名 / 频段 / 启用状态（只改清单，部署后生效） */
	function showEditLine(idx, ssid, band, enabled) {
		var old = document.getElementById('tk-edit-modal');
		if (old && old.parentNode) { old.parentNode.removeChild(old); }
		var mask = el('div', 'tk-modal-mask');
		mask.id = 'tk-edit-modal';
		var box = el('div', 'tk-modal');
		var head = el('div', 'tk-modal-head');
		head.appendChild(el('b', null, '编辑线路 #' + idx));
		var x = el('button', 'tk-modal-x', '×');
		x.type = 'button';
		x.addEventListener('click', function () { mask.parentNode.removeChild(mask); });
		head.appendChild(x);
		box.appendChild(head);
		var body = el('div', 'tk-modal-body');
		function field(label, node) {
			var row = el('div');
			row.style.display = 'flex'; row.style.alignItems = 'center';
			row.style.gap = '0.6rem'; row.style.margin = '0.45rem 0';
			var k = el('span', null, label);
			k.style.width = '6.5rem'; k.style.color = '#5b6472'; k.style.fontSize = '13px';
			row.appendChild(k); row.appendChild(node);
			return row;
		}
		var inSsid = document.createElement('input');
		inSsid.type = 'text'; inSsid.className = 'cbi-input-text';
		inSsid.value = ssid || ''; inSsid.maxLength = 32; inSsid.style.flex = '1';
		body.appendChild(field('SSID 名称', inSsid));
		// 频段决定这颗射频、网段、桥与端口，改动等于重建线路 —— 只读
		var bandTxt = (band === '5g') ? '5G' : ((band === 'both') ? '双频（2.4G + 5G）' : '2.4G');
		var bandSpan = el('span', null, bandTxt + '（不可修改）');
		bandSpan.style.color = '#8a93a0'; bandSpan.style.fontSize = '13px';
		body.appendChild(field('频段', bandSpan));

		// WiFi 密码：全局一份（所有 SSID 共用），留空表示不改
		var inPw = document.createElement('input');
		inPw.type = 'text'; inPw.className = 'cbi-input-text';
		inPw.placeholder = '8-63 位'; inPw.style.flex = '1';
		body.appendChild(field('WiFi 密码', inPw));
		var pwTip = el('div', 'tk-modal-src');
		pwTip.textContent = '密码只作用于这一条 SSID（每条可以不一样），留空表示不改。';
		// 打开即显示当前密码（来源：本条自定义 / 设备生效 / 全局），可直接改
		postBind('line_info', { idx: idx }).then(function (r) {
			if (!r || !r.ok) { return; }
			inPw.value = r.key || '';
			var srcTxt = (r.key_source === 'line') ? '本条 SSID 自定义'
				: (r.key_source === 'device' ? '设备当前生效（部署时下发）' : '全局默认');
			pwTip.textContent = '当前密码：' + (r.key ? r.key : '（未设置）') + '　来源：' + srcTxt
				+ '。可直接改；改完点「仅保存」或「保存并部署」。';
		}).catch(function () { /* 取不到就留空 */ });
		body.appendChild(pwTip);
		var inEn = document.createElement('select');
		inEn.className = 'cbi-input-select';
		[['1', '已启用'], ['0', '已禁止']].forEach(function (pr) {
			var o = document.createElement('option');
			o.value = pr[0]; o.textContent = pr[1];
			if ((enabled ? '1' : '0') === pr[0]) { o.selected = true; }
			inEn.appendChild(o);
		});
		body.appendChild(field('状态', inEn));
		var tip = el('div', 'tk-modal-src');
		tip.textContent = '「仅保存」只写清单；「保存并部署」立刻按新配置重建这条 SSID（约 10-30 秒，期间该 WiFi 会短暂断开）。';
		body.appendChild(tip);
		box.appendChild(body);

		var ft = el('div', 'tk-modal-ft');
		var btnOk = el('button', 'cbi-button', '仅保存');
		btnOk.type = 'button';
		var btnApply = el('button', 'cbi-button cbi-button-apply', '保存并部署');
		btnApply.type = 'button';
		var btnCancel = el('button', 'cbi-button', '取消');
		btnCancel.type = 'button';
		btnCancel.addEventListener('click', function () { mask.parentNode.removeChild(mask); });
		ft.appendChild(btnOk); ft.appendChild(btnApply); ft.appendChild(btnCancel);
		box.appendChild(ft);

			function submitEdit(andDeploy) {
				var req = {
					idx: idx,
					ssid: inSsid.value.replace(/^\s+|\s+$/g, ''),
					band: band,
					enabled: inEn.value
				};
				var pw = inPw.value;
				if (pw !== '') { req.password = pw; } else if (inPw.value !== '' || false) { /* 空表示不改 */ }
				btnOk.disabled = true; btnApply.disabled = true;
				postBind('line_update', req).then(function (r) {
					btnOk.disabled = false; btnApply.disabled = false;
					if (!r || r.ok === false) { window.alert((r && r.msg) || '保存失败'); return; }
					if (!andDeploy) {
						mask.parentNode.removeChild(mask);
						if (typeof markDirty === 'function') { markDirty(); }
						refreshPending();
						reloadTable().catch(function () { /* 静默 */ });
						return;
					}
					// 保存并部署：直接触发部署，不用再去点按钮
					if (typeof postDeploy === 'function') {
						mask.parentNode.removeChild(mask);
						if (typeof markDirty === 'function') { markDirty(); }
						refreshPending();
						postDeploy();
					} else {
						mask.parentNode.removeChild(mask);
						refreshPending();
						reloadTable().catch(function () { /* 静默 */ });
						window.alert('已保存。部署按钮未就绪，请在概览页点「保存并部署」。');
					}
			}).catch(function (e) {
			btnOk.disabled = false;
			btnApply.disabled = false;
			var why = (e && (e.message || e.toString())) || '未知错误';
			if (window.console) { console.error('[tkproxy] 保存并部署失败：', e); }
			window.alert('操作失败：' + why);
		});
			}

			btnOk.addEventListener('click', function () { submitEdit(false); });
			btnApply.addEventListener('click', function () { submitEdit(true); });
		mask.appendChild(box);
		mask.addEventListener('click', function (ev) {
			if (ev.target === mask) { mask.parentNode.removeChild(mask); }
		});
		document.body.appendChild(mask);
	}

	function bindTableEvents() {
		/* 服务端渲染的行缺「编辑 / 保存并部署」按钮：按行数据补上（幂等，逐个判断） */
		Array.prototype.forEach.call(document.querySelectorAll('tr[data-row]'), function (tr) {
			var act = tr.querySelector('.tk-col-act');
			if (!act) { return; }
			var idx = tr.getAttribute('data-row');
			// 「编辑」缺才补（有 data-line-edit 就不再加）
			if (!act.querySelector('[data-line-edit]')) {
				var ssidEl = tr.querySelector('.tk-ssid');
				var ssid = tr.getAttribute('data-ssid') || (ssidEl ? ssidEl.textContent : '');
				var bandEl = tr.querySelector('.tk-band');
				var bt = bandEl ? bandEl.textContent : '';
				var band = '2g';
				if (bt.indexOf('5G') >= 0) { band = '5g'; }
				else if (bt.indexOf('双频') >= 0) { band = 'both'; }
				var tg = tr.querySelector('[data-bind-toggle]');
				var en = tg ? tg.getAttribute('data-enabled') : '1';
				var b = el('button', 'cbi-button tk-btn-sm tk-btn-edit', '编辑');
				b.type = 'button';
				b.setAttribute('data-line-edit', idx);
				b.setAttribute('data-ssid-name', ssid);
				b.setAttribute('data-band-name', band);
				b.setAttribute('data-enabled-flag', (en === '0') ? '0' : '1');
				// 统一锚点：都插到「删除」之前，保证「编辑 → 保存并部署 → 删除」顺序幂等
				act.insertBefore(b, act.querySelector('[data-bind-del]') || null);
			}
			// 「保存并部署」缺才补：编辑按钮存在不代表行内部署按钮存在（3.12.0 之前的行就没有）
			if (!act.querySelector('[data-line-deploy]')) {
				var bd = el('button', 'cbi-button tk-btn-sm cbi-button-apply', '保存并部署');
				bd.type = 'button';
				bd.setAttribute('data-line-deploy', idx);
				bd.title = '只重建这一条线路（约 10-30 秒），不会动其它 SSID';
				act.insertBefore(bd, act.querySelector('[data-bind-del]') || null);
			}
		});

		/* 单行编辑按钮 */
		Array.prototype.forEach.call(document.querySelectorAll('[data-line-deploy]'), function (btn) {
			btn.addEventListener('click', function () { deployOneLine(btn); });
		});
		Array.prototype.forEach.call(document.querySelectorAll('[data-line-edit]'), function (btn) {
			btn.addEventListener('click', function () {
				showEditLine(btn.getAttribute('data-line-edit'),
					btn.getAttribute('data-ssid-name') || '',
					btn.getAttribute('data-band-name') || '2g',
					btn.getAttribute('data-enabled-flag') === '1');
			});
		});
		/* 启用 / 禁用：两态按钮，点击即切换 */
		var toggles = document.querySelectorAll('[data-bind-toggle]');
		Array.prototype.forEach.call(toggles, function (btn) {
			btn.addEventListener('click', function () {
				var idx = btn.getAttribute('data-bind-toggle');
				var nowOn = btn.getAttribute('data-enabled') === '1';
				var nextOn = !nowOn;
				btn.disabled = true;
				postBind('bind_toggle', { idx: idx, enabled: nextOn ? '1' : '0' }).then(function (r) {
					btn.disabled = false;
					if (!r || r.ok === false) {
						window.alert((r && (r.msg || r.error)) || '切换失败');
						return;
					}
					btn.setAttribute('data-enabled', nextOn ? '1' : '0');
					btn.textContent = nextOn ? '已启用' : '已禁止';
					btn.className = 'tk-en-btn ' + (nextOn ? 'is-on' : 'is-off');
					var tr = btn.closest('tr');
					if (tr) { tr.style.opacity = nextOn ? '1' : '.55'; }
					markDirty();
				}).catch(function () { btn.disabled = false; });
			});
		});

		/* 节点下拉 */
		var sels = document.querySelectorAll('[data-bind-select]');
		Array.prototype.forEach.call(sels, function (sel) {
			sel.addEventListener('change', function () {
				var idx = sel.getAttribute('data-bind-select');
				sel.disabled = true;
				postBind('bind_set', { idx: idx, node: sel.value }).then(function (r) {
					sel.disabled = false;
					if (!r || r.ok === false) {
						window.alert((r && (r.msg || r.error)) || '绑定失败');
						reloadTable();
						return;
					}
					reloadTable().catch(function () { /* 静默 */ });
				}).catch(function () { sel.disabled = false; reloadTable(); });
			});
		});

		/* 单行检测按钮（.tk-btn-check）→ 调 env_check，加硬超时与必定复位 */
		var checkBtns = document.querySelectorAll('.tk-btn-check[data-line]');
		Array.prototype.forEach.call(checkBtns, function (btn) {
			btn.addEventListener('click', function () {
				var lineNum = btn.getAttribute('data-line');
				var tr = btn.closest('tr');
				if (!tr) { return; }

				var onlineCell = $('[data-col="online"]', tr);
				var envCell = $('[data-col="env"]', tr);
				var exitCell = $('[data-col="exit"]', tr);

				btn.disabled = true;
				var origText = btn.textContent;
				btn.textContent = '检测中';

				// 25 秒硬超时
				var timeout = 60000;
				var timeoutId = setTimeout(function () {
					// 超时强制复位
					btn.disabled = false;
					btn.textContent = origText;
					cacheLineResult(lineNum, { ok: false, status: 'fail', note: '检测超时（60秒）' });
					if (onlineCell) {
						while(onlineCell.firstChild) onlineCell.removeChild(onlineCell.firstChild);
						var badge = el('span', 'tk-badge is-bad', '不通');
						badge.title = '检测超时（60秒）';
						onlineCell.appendChild(badge);
						onlineCell.className = '';
					}
					if (envCell) {
						while(envCell.firstChild) envCell.removeChild(envCell.firstChild);
						envCell.className = '';
						var envBadge = el('span', 'tk-badge is-muted', '未检测');
						envBadge.title = '超时，未取到环境数据';
						envCell.appendChild(envBadge);
					}
					if (exitCell) {
						exitCell.textContent = '检测超时';
						exitCell.className = 'tk-muted';
						exitCell.title = '超过 60 秒未返回';
					}
				}, timeout);

				post('purity_line', { line: lineNum }).then(function (r) {
					clearTimeout(timeoutId);
					btn.disabled = false;
					btn.textContent = origText;

					if (!r || !r.ok) {
						// 后端返回失败：填失败原因
						cacheLineResult(lineNum, { ok: false, status: 'fail', note: (r && (r.note || r.msg)) || '检测失败' });
						if (onlineCell) {
							while(onlineCell.firstChild) onlineCell.removeChild(onlineCell.firstChild);
							var badge = el('span', 'tk-badge is-bad', '不通');
							badge.title = (r && r.note) || '检测失败';
							onlineCell.appendChild(badge);
							onlineCell.className = '';
						}
						if (envCell) {
							while(envCell.firstChild) envCell.removeChild(envCell.firstChild);
							envCell.className = '';
							var envBadge = el('span', 'tk-badge is-muted', '未检测');
							envCell.appendChild(envBadge);
						}
						if (exitCell) {
							exitCell.textContent = (r && r.note) || '检测失败';
							exitCell.className = 'tk-muted';
							exitCell.title = (r && r.note) || '';
						}
						return;
					}

					// 成功：解析检测返回字段
					var exit_ip = r.exit_ip || '';
					// 状态列以「是否取到出口 IP」为准；接口不再返回 status 时不能回落成 fail
					var status = r.status || (exit_ip ? 'ok' : 'fail');
					var env_country = r.country || r.env_country || '';
					var env_isp = r.isp || r.env_isp || '';
					var dns_loc = r.dns_country || r.dns_loc || '';
					var dns_ok = (typeof r.dns_consistent === 'boolean') ? r.dns_consistent : r.dns_ok;
					var ipv6_leak = r.ipv6_leak;
					var direct_leak = r.direct_leak;
					var verdict = r.verdict || (exit_ip ? 'pass' : 'fail');
					var ip_type = r.ip_type || '';
					var reasons = '';
					if (r.reasons && r.reasons.join) { reasons = r.reasons.join('；'); }
					else if (typeof r.reasons === 'string') { reasons = r.reasons; }
					var note = reasons || r.note || '';

					// 落缓存：这一行的检测结果此后恒定显示，状态轮询不再覆盖
					cacheLineResult(lineNum, {
						ok: true, status: status, exit_ip: exit_ip, verdict: verdict,
						ip_type: ip_type, note: note, country: env_country, isp: env_isp,
						dns_loc: dns_loc, dns_ok: dns_ok, ipv6_leak: ipv6_leak, direct_leak: direct_leak
					});

					// 状态列：status==='ok' → 绿「通」，否则红「不通」
					if (onlineCell) {
						while(onlineCell.firstChild) onlineCell.removeChild(onlineCell.firstChild);
						onlineCell.className = '';
						var badge = el('span', 'tk-en-btn ' + (status === 'ok' ? 'is-on' : 'is-off'),
							status === 'ok' ? '通' : '不通');
						badge.title = note;
						onlineCell.appendChild(badge);
					}

					// 运营环境列：status==='fail' → 红「不可用」；否则按风险判定
					if (envCell) {
						while(envCell.firstChild) envCell.removeChild(envCell.firstChild);
						envCell.className = '';
						var envCls, envTxt;
						var titleParts = [];
						if (verdict === 'fail') {
							envCls = 'is-bad-t';
							envTxt = '不可用';
							titleParts.push(ip_type ? ('IP 类型：' + ip_type) : '');
							if (note) titleParts.push(note);
						} else if (verdict === 'risk') {
							envCls = 'is-warn-t';
							envTxt = '有风险';
							if (note) titleParts.push(note);
						} else if (verdict === 'pass') {
							envCls = 'is-ok-t';
							envTxt = '可用';
							titleParts.push(ip_type ? ('IP 类型：' + ip_type) : '住宅 IP');
						} else if (status === 'fail') {
							envCls = 'is-bad-t';
							envTxt = '不可用';
							if (note) titleParts.push(note);
						} else {
							// 三风险项：dns_ok===false、ipv6_leak===true、direct_leak===true
							var risks = [];
							if (dns_ok === false) { risks.push('DNS落地不一致'); }
							if (ipv6_leak === true) { risks.push('IPv6泄漏'); }
							if (direct_leak === true) { risks.push('直连泄漏'); }
							if (risks.length > 0) {
								envCls = 'is-warn-t';
								envTxt = '有风险';
								titleParts.push('风险项：' + risks.join(' / '));
							} else {
								envCls = 'is-ok-t';
								envTxt = '可用';
							}
						}
						var envClsMap = { 'is-ok-t': 'is-on', 'is-bad-t': 'is-off', 'is-warn-t': 'is-warn' };
						var envBadge = el('span', 'tk-en-btn ' + (envClsMap[envCls] || 'is-warn'), envTxt);
						envBadge.title = titleParts.join('\n');
						envBadge.style.cursor = 'pointer';
						envBadge.addEventListener('click', function (ev) {
							ev.stopPropagation();
							var tr2 = envCell.closest('tr');
							var ssid = '';
							if (tr2) { var b = tr2.querySelector('b'); if (b) { ssid = (b.textContent || '').trim(); } }
							var ipOk = !!(exit_ip && exit_ip !== '');
							var checks = [
								{ name: 'IP 质量', status: (verdict === 'pass' ? 'pass' : (verdict === 'risk' ? 'risk' : 'fail')),
								  detail: (ip_type || '未判定') + (note ? ('：' + note) : '') },
								{ name: 'DNS 落地一致', status: (dns_ok === false ? 'fail' : 'pass'),
								  detail: '解析侧 ' + (dns_loc || '?') + ' / 出口 ' + (env_country || '?') },
								{ name: 'IPv6 泄漏', status: (ipv6_leak === true ? 'fail' : 'pass'),
								  detail: (ipv6_leak === true ? '检测到 IPv6 泄漏' : '未发现泄漏') },
								{ name: '直连绕过', status: (direct_leak === true ? 'fail' : 'pass'),
								  detail: (direct_leak === true ? '出口 IP 与直连相同' : '未发现') },
								{ name: '出口 IP 唯一', status: 'na', detail: '单行检测不比对全表' }
							];
							if (typeof showEnvDetail === 'function') {
								showEnvDetail({
									ssid: ssid || ('TK-' + lineNum),
									line: lineNum,
									lineNum: lineNum,
									line_ok: ipOk,
									exit_ip: exit_ip || '',
									country: env_country || '',
									org: (env_isp || '') + ((r.asn || '') ? (' / ' + r.asn) : ''),
									asn: r.asn || '',
									ip_type: ip_type || '',
									proxy: r.proxy || false,
									reverse: r.reverse || '',
									dns_upstream: r.dns_upstream || '1.1.1.1',
									dns_country: dns_loc || '',
									trace_country: r.trace_country || '',
									dns_consistent: dns_ok,
									verdict: verdict,
									conclusion: r.conclusion || '',
									override: r.override || 0,
									raw_quality: r.raw_quality || '',
									probe: r.probe || null,
									env_level: r.env_level || '',
									env_miss: r.env_miss || '',
									env_risk: r.env_risk || '',
									summary: r.summary || '',
									checks: checks
								});
							}
						});
						envCell.appendChild(envBadge);
					}

					// 出口 IP 列：env_country + ' ' + exit_ip
					if (exitCell) {
						while(exitCell.firstChild) exitCell.removeChild(exitCell.firstChild);
						if (exit_ip && exit_ip !== '') {
							var displayText = (env_country ? env_country + ' ' : '') + exit_ip;
							var span = el('span', 'tk-cell-clamp', displayText);
							var titleLines = [];
							titleLines.push('出口 IP：' + exit_ip);
							if (env_country) titleLines.push('出口国家：' + env_country);
							if (env_isp) titleLines.push('运营商：' + env_isp);
							if (dns_loc) titleLines.push('DNS 落地：' + dns_loc);
							span.title = titleLines.join('\n');
							exitCell.appendChild(span);
							exitCell.className = 'tk-mono';
						} else {
							exitCell.textContent = note || '无数据';
							exitCell.className = 'tk-muted';
							exitCell.title = note || '';
						}
					}
				}).catch(function (e) {
					clearTimeout(timeoutId);
					btn.disabled = false;
					btn.textContent = origText;
					// 异常（网络/解析错误）：复位按钮并写失败原因
					cacheLineResult(lineNum, { ok: false, status: 'fail', note: '请求失败：' + (e && e.message ? e.message : '') });
					if (onlineCell) {
						while(onlineCell.firstChild) onlineCell.removeChild(onlineCell.firstChild);
						var badge = el('span', 'tk-badge is-bad', '不通');
						badge.title = '请求失败：' + (e && e.message ? e.message : '');
						onlineCell.appendChild(badge);
						onlineCell.className = '';
					}
					if (envCell) {
						while(envCell.firstChild) envCell.removeChild(envCell.firstChild);
						envCell.className = '';
						var envBadge = el('span', 'tk-badge is-muted', '未检测');
						envCell.appendChild(envBadge);
					}
					if (exitCell) {
						exitCell.textContent = '请求失败';
						exitCell.className = 'tk-muted';
						exitCell.title = e && e.message ? e.message : '';
					}
				});
			});
		});

		/* 删除按钮 */
		var dels = document.querySelectorAll('[data-bind-del]');
		Array.prototype.forEach.call(dels, function (btn) {
			btn.addEventListener('click', function () {
				var idx = btn.getAttribute('data-bind-del');
				var tr = btn.closest('tr');
				var ssid = tr ? tr.getAttribute('data-ssid') : '';
				if (!armConfirm(btn, {
					armText: '再点一次确认删除',
					restoreText: '删除',
					onConfirm: function () { /* 继续执行下面的删除 */ }
				})) { return; }
				btn.disabled = true;
				postBind('line_delete', { idx: idx }).then(function (r) {
					btn.disabled = false;
					if (!r || r.ok === false) {
						window.alert((r && r.msg) || '删除失败');
						refreshOrReload('删除失败');
						return;
					}
					if (tr && tr.parentNode) { tr.parentNode.removeChild(tr); }
					markDirty();
					reloadTable().catch(function () { /* 静默 */ });
				}).catch(function () { btn.disabled = false; });
			});
		});
	}

	function bindWorkbench() {
		function out(sel, cls, text) {
			var box = $(sel);
			if (!box) { return; }
			clear(box);
			box.hidden = false;
			box.className = 'tk-check-summary ' + cls;
			var d = el('div', null, text);
			d.textContent = text;
			box.appendChild(d);
		}

		// 标记「有改动未部署」：uci 已保存，但要生效需部署
		function markDirty() {
			var d = $('[data-tk-dirty]');
			if (d) { d.hidden = false; }
			refreshPending();
		}

		/* 解析预览：纯本地解析，不发请求、不改数据 */
		/* ---------- Clash 配置 → 节点链接（支持 vless/ws/tls/reality、ss、trojan、vmess） ---------- */
	function clashToLinks(text) {
		if (!/^\s*(port|proxies|proxy-groups|mixed-port|socks-port)\s*:/m.test(text)) { return text; }
		var lines = text.split(/\r?\n/);
		var out = [], cur = null, inProxies = false;

		function flush() {
			if (!cur || !cur.type || !cur.server || !cur.port) { cur = null; return; }
			var t = (cur.type || '').toLowerCase();
			var name = encodeURIComponent(cur.name || (cur.server + ':' + cur.port));
			var q = [];
			function push(k, v) { if (v !== undefined && v !== null && v !== '') { q.push(k + '=' + encodeURIComponent(v)); } }
			if (t === 'vless' || t === 'vmess') {
				var net = cur.network || 'tcp';
				push('encryption', t === 'vless' ? 'none' : undefined);
				push('security', cur.tls ? (cur['reality-opts'] ? 'reality' : 'tls') : (net === 'ws' && cur.tls ? 'tls' : 'none'));
				push('type', net);
				push('sni', cur.servername || cur.sni);
				push('host', cur.host || (cur['ws-opts'] && cur['ws-opts'].headers && cur['ws-opts'].headers.Host));
				push('path', cur['ws-opts'] && cur['ws-opts'].path);
				push('fp', cur['client-fingerprint']);
				push('pbk', cur['reality-opts'] && cur['reality-opts']['public-key']);
				push('sid', cur['reality-opts'] && cur['reality-opts']['short-id']);
				push('flow', cur.flow);
				out.push(t + '://' + (cur.uuid || '') + '@' + cur.server + ':' + cur.port +
					(q.length ? '?' + q.join('&') : '') + '#' + name);
			} else if (t === 'ss' || t === 'shadowsocks') {
				var m = (cur.cipher || 'aes-128-gcm') + ':' + (cur.password || '');
				out.push('ss://' + btoa(m) + '@' + cur.server + ':' + cur.port + '#' + name);
			} else if (t === 'trojan') {
				push('sni', cur.servername || cur.sni);
				push('type', cur.network || 'tcp');
				out.push('trojan://' + (cur.password || '') + '@' + cur.server + ':' + cur.port +
					(q.length ? '?' + q.join('&') : '') + '#' + name);
			}
			cur = null;
		}

		lines.forEach(function (ln) {
			if (/^\s*proxies\s*:/.test(ln)) { inProxies = true; return; }
			if (inProxies && /^\S/.test(ln) && !/^\s*-/.test(ln)) { inProxies = false; flush(); }
			if (!inProxies) { return; }
			var mItem = ln.match(/^\s*-\s*(?:\{(.*)\}|(.*))$/);
			if (mItem) {
				flush();
				cur = {};
				if (mItem[1]) {
					mItem[1].split(/,\s*(?=[a-zA-Z-]+\s*:)/).forEach(function (kv) {
						var p = kv.split(/\s*:\s*/);
						if (p.length === 2) { cur[p[0].trim()] = p[1].replace(/^["']|["']$/g, ''); }
					});
					flush();
				}
				return;
			}
			var mKV = ln.match(/^\s+([a-zA-Z-]+)\s*:\s*(.+)$/);
			if (mKV && cur) { cur[mKV[1]] = mKV[2].replace(/^["']|["']$/g, '').trim(); }
		});
		flush();
		return out.length ? out.join('\n') : text;
	}

	/* 把导入框里的 Clash 配置就地转成链接 */
	function normalizeImportText() {
		var box = document.getElementById('tk-wb-nodes');
		if (!box || !box.value) { return ''; }
		var conv = clashToLinks(box.value);
		if (conv !== box.value) {
			box.value = conv;
			var head = document.querySelector('[data-wb-preview-head]');
			if (head) { head.textContent = '已识别 Clash 配置，自动转换成 ' + conv.split('\n').length + ' 条节点链接'; }
		}
		return box.value;
	}

	function localPreview() {
			var ta = $('#tk-wb-nodes');
			var box = $('[data-wb-preview]');
			var head = $('[data-wb-preview-head]');
			var body = $('[data-wb-preview-body]');
			if (!ta || !box || !body) { return; }

			// 现有节点名（用于判重）：从表格里的下拉选项收集
			var exist = {};
			var firstSel = $('[data-bind-select]');
			if (firstSel) {
				Array.prototype.forEach.call(firstSel.options, function (o) {
					if (o.value) { exist[o.value] = true; }
				});
			}

			var lines = (ta.value || '').replace(/\r/g, '').split('\n');
			var okN = 0, badN = 0, dupN = 0, seen = {};
			clear(body);
			lines.forEach(function (raw, i) {
				var line = (raw || '').trim();
				if (!line) { return; }
				var tr = el('tr');
				tr.appendChild(el('td', null, String(i + 1)));

				var scheme = '未知';
				var m = line.match(/^([a-z0-9]+):\/\//i);
				if (m) { scheme = m[1].toLowerCase(); }
				else if (line.indexOf('json:') === 0) { scheme = 'hysteria2'; }

				// 合法判定：协议头对 + 真的有主机端口（或 json 里真的有 server/port）
				var schemeOk = /^(vless|vmess|trojan|ss|hysteria2):\/\//i.test(line) || line.indexOf('json:') === 0;
				var hasHostPort = /@[\w.\-]+:\d+/.test(line) || /\/\/[\w.\-]+:\d+/.test(line);
				var isJson = line.indexOf('json:') === 0;
				var jsonOk = /"server"\s*:/.test(line) && /"server_port"\s*:/.test(line);
				// ss:// 可能是整段 base64（无 @host:port），只要够长就放行
				var ssB64 = /^ss:\/\//i.test(line) && line.length > 20;
				var valid = schemeOk && (isJson ? jsonOk : (hasHostPort || ssB64));

				var name = '';
				var hi = line.indexOf('#');
				if (hi >= 0) {
					try { name = decodeURIComponent(line.slice(hi + 1)); } catch (e2) { name = line.slice(hi + 1); }
				}
				name = (name || '').replace(/\|/g, '/').trim();
				if (!name && line.indexOf('json:') === 0) {
					var mh2 = line.match(/"server"\s*:\s*"([^"]+)"/);
					if (mh2) { name = mh2[1]; }
				}

				var host = '';
				var mh = line.match(/@([\w.\-]+):(\d+)/) || line.match(/\/\/([\w.\-]+):(\d+)/);
				if (mh) {
					var parts = mh[1].split('.');
					host = (parts.length >= 2) ? (parts[0] + '.' + parts[1] + '.***') : mh[1];
				}

				var dup = false;
				if (name && (seen[name] || exist[name])) { dup = true; }
				if (name) { seen[name] = true; }

				if (valid) { okN++; } else { badN++; }
				if (dup) { dupN++; }

				tr.appendChild(el('td', null, name || '（无名称）'));
				tr.appendChild(el('td', null, scheme));
				tr.appendChild(el('td', null, host || '—'));
				var tdD = el('td', null, dup ? '重复' : '新');
				if (dup) { tdD.style.color = '#c98a00'; }
				tr.appendChild(tdD);
				var tdV = el('td', null, valid ? '合法' : '非法');
				if (!valid) { tdV.style.color = '#c0392b'; }
				tr.appendChild(tdV);
				body.appendChild(tr);
			});

			if (head) {
				head.textContent = '共 ' + (okN + badN) + ' 行：合法 ' + okN +
					'，非法 ' + badN + '，与现有重复 ' + dupN;
			}
			box.hidden = false;
		}

		var btnPreview = $('[data-tk-act="wb-preview"]');
		if (btnPreview) {
			btnPreview.addEventListener('click', function () { localPreview(); });
		}

		/* 条数：− / ＋ / 填满剩余名额 */
		function bandRemain(band) {
			var lim = parseInt(root.getAttribute('data-tk-limit') || '16', 10) || 16;
			var used = parseInt(root.getAttribute(band === '2g' ? 'data-tk-used-2g' : 'data-tk-used-5g') || '0', 10) || 0;
			// 5G(radio1) 上还挂着主 AP，占 1 个名额
			if (band === '5g' && deployed) { used = used + 1; }
			var rem = lim - used;
			return rem > 0 ? rem : 0;
		}

		$all('[data-tk-step]').forEach(function (btn) {
			btn.addEventListener('click', function () {
				var spec = btn.getAttribute('data-tk-step') || '';
				var ix = spec.lastIndexOf(':');
				var id = spec.slice(0, ix);
				var delta = parseInt(spec.slice(ix + 1), 10) || 0;
				var inp = document.getElementById(id);
				if (!inp) { return; }
				var v = parseInt(inp.value || '1', 10) || 1;
				v = v + delta;
				if (v < 1) { v = 1; }
				if (v > 16) { v = 16; }
				inp.value = String(v);
			});
		});

		$all('[data-tk-fill]').forEach(function (btn) {
			btn.addEventListener('click', function () {
				var band = btn.getAttribute('data-tk-fill');
				var inp = document.getElementById('tk-' + band + '-count');
				if (!inp) { return; }
				var rem = bandRemain(band);
				if (rem <= 0) {
					inp.value = '1';
					out('[data-wb-create-out]', 'is-bad',
						(band === '2g' ? '2.4G' : '5G') + ' 射频名额已满（' +
						(root.getAttribute('data-tk-limit') || '16') + '/16），先禁止或删除部分线路');
					return;
				}
				inp.value = String(rem);
			});
		});

		/* ① 导入节点 */
		var btnImp = $('[data-tk-act="wb-import"]');
		if (btnImp) {
			btnImp.addEventListener('click', function () {
				var ta = $('#tk-wb-nodes');
				if (!ta || !ta.value.trim()) {
					out('[data-wb-import-out]', 'is-bad', '请先粘贴节点链接');
					return;
				}
				btnImp.disabled = true;
				out('[data-wb-import-out]', 'is-idle', '正在解析并导入…');
				postBind('nodes_import', { text: ta.value }).then(function (r) {
					btnImp.disabled = false;
					if (!r || r.ok === false) {
						var m0 = (r && (r.msg || r.error)) || '导入失败';
						if (r && r.bad_lines && r.bad_lines.length) {
							var un = r.bad_lines.filter(function (b) { return b.reason && b.reason.indexOf('不支持') >= 0; });
							if (un.length) {
								m0 += '｜不支持的协议第 ' + un.map(function (b) { return b.line; }).join('、') + ' 行：'
									+ un[0].reason.replace(/（.*$/, '');
							}
						}
						out('[data-wb-import-out]', 'is-bad', m0);
						return;
					}
					var msg = '已导入 ' + (r.imported || 0) + ' 条';
					if (r.duplicated) { msg += '，重复跳过 ' + r.duplicated + ' 条'; }
					if (r.bad_lines && r.bad_lines.length) {
						var nums = r.bad_lines.slice(0, 5).map(function (b) { return b.line || b; });
						msg += '；' + r.bad_lines.length + ' 行被跳过（第 ' + nums.join('、') + ' 行）';
						var un2 = r.bad_lines.filter(function (b) { return b.reason && b.reason.indexOf('不支持') >= 0; });
						if (un2.length) { msg += '，其中 ' + un2.length + ' 行的协议不支持'; }
					}
					out('[data-wb-import-out]', 'is-online', msg);
					ta.value = '';
					reloadTable();
				}).catch(function () {
					btnImp.disabled = false;
					out('[data-wb-import-out]', 'is-bad', '导入请求失败');
				});
			});
		}

		/* ② 创建 WiFi：2.4G 与 5G 完全分开，各自一个按钮 */
		function createBand(btn, band, outSel) {
			var pre = (band === '2g') ? 'tk-2g-' : 'tk-5g-';
			function val(name, dflt) {
				var n = document.getElementById(pre + name);
				return (n && n.value !== '') ? n.value : dflt;
			}
			var n = parseInt(val('count', '0'), 10) || 0;
			if (n < 1) {
				out(outSel, 'is-bad', '条数至少填 1');
				return;
			}
			if (!armConfirm(btn, { doneText: '刷新页面' })) { return; }
			btn.disabled = true;
			out(outSel, 'is-idle', (band === '2g' ? '正在创建 2.4G WiFi…' : '正在创建 5G WiFi…'));
			post('batch_generate', {
				mode: 'manual',
				count: n,
				count_2g: (band === '2g') ? n : 0,
				count_5g: (band === '5g') ? n : 0,
				prefix: val('prefix', band === '2g' ? 'TK2.4G-' : 'TK5G-'),
				start_seq: val('start', '1'),
				password: val('pass', '')
			}).then(function (r) {
				btn.disabled = false;
				if (!r || r.ok === false) {
					out(outSel, 'is-bad', (r && r.msg) || '创建失败');
					return;
				}
				out(outSel, 'is-online', '已创建 ' + n + ' 条 ' +
					(band === '2g' ? '2.4G' : '5G') + ' WiFi　' + (r.msg || ''));
				scrollToTable();
				refreshOrReload('创建 WiFi');
			}).catch(function () {
				btn.disabled = false;
				out(outSel, 'is-bad', '创建请求失败');
			});
		}

		var btn2g = $('[data-tk-act="wb-create-2g"]');
		if (btn2g) {
			btn2g.addEventListener('click', function () { createBand(btn2g, '2g', '[data-wb-create-out]'); });
		}
		var btn5g = $('[data-tk-act="wb-create-5g"]');
		if (btn5g) {
			btn5g.addEventListener('click', function () { createBand(btn5g, '5g', '[data-wb-create-out]'); });
		}

		/* 工具条：自动绑定 */
		var btnAuto = $('[data-tk-act="auto-bind"]');
		if (btnAuto) {
			btnAuto.addEventListener('click', function () {
				btnAuto.disabled = true;
				postBind('bind_auto').then(function (r) {
					btnAuto.disabled = false;
					if (!r || r.ok === false) {
						window.alert((r && r.msg) || '自动绑定失败');
						return;
					}
					window.alert(r.msg || '已自动绑定');
					reloadTable();
				}).catch(function () {
					btnAuto.disabled = false;
					window.alert('请求失败');
				});
			});
		}

		/* 工具条：清空全部线路（两段式确认） */
		var btnClearLines = $('[data-tk-act="lines-clear"]');
		if (btnClearLines) {
			btnClearLines.addEventListener('click', function () {
				if (!armConfirm(btnClearLines, {
					armText: '再点一次清空全部线路',
					restoreText: '清空全部线路',
					onConfirm: function () { /* 继续 */ }
				})) { return; }
				btnClearLines.disabled = true;
				postBind('line_clear').then(function (r) {
					btnClearLines.disabled = false;
					if (!r || r.ok === false) {
						window.alert((r && r.msg) || '清空失败');
						return;
					}
					markDirty();
					reloadTable().catch(function () { /* 静默 */ });
				}).catch(function () { btnClearLines.disabled = false; });
			});
		}

		/* 工具条：全部启用 */
		var btnEnAll = $('[data-tk-act="enable-all"]');
		if (btnEnAll) {
			btnEnAll.addEventListener('click', function () {
				var cbs = $all('[data-bind-toggle]');
				var todo = [];
				cbs.forEach(function (cb) {
					if (cb.getAttribute('data-enabled') !== '1') { todo.push(cb.getAttribute('data-bind-toggle')); }
				});
				if (!todo.length) { window.alert('全部已启用'); return; }
				btnEnAll.disabled = true;
				var done = 0;
				function next() {
					if (done >= todo.length) {
						btnEnAll.disabled = false;
						reloadTable();
						return;
					}
					postBind('bind_toggle', { idx: todo[done], enabled: '1' }).then(function () {
						done += 1;
						next();
					}).catch(next);
				}
				next();
			});
		}

		/* 工具条：全部禁用 */
		var btnDisAll = $('[data-tk-act="disable-all"]');
		if (btnDisAll) {
			btnDisAll.addEventListener('click', function () {
				var cbs = $all('[data-bind-toggle]');
				var todo = [];
				cbs.forEach(function (cb) {
					if (cb.getAttribute('data-enabled') === '1') { todo.push(cb.getAttribute('data-bind-toggle')); }
				});
				if (!todo.length) { window.alert('全部已禁用'); return; }
				btnDisAll.disabled = true;
				var done = 0;
				function next() {
					if (done >= todo.length) {
						btnDisAll.disabled = false;
						reloadTable();
						return;
					}
					postBind('bind_toggle', { idx: todo[done], enabled: '0' }).then(function () {
						done += 1;
						next();
					}).catch(next);
				}
				next();
			});
		}

		// 首次加载表格
		var tbody = $('#tk-bind-tbody');
		if (tbody && tbody.children.length > 0) {
			var rows = [];
			Array.prototype.forEach.call(tbody.children, function (tr) {
				// band 一并收集：updateStats 现在还要刷新名额摘要，缺 band 会误计
				var bandEl = tr.querySelector('.tk-band');
				var bt = bandEl ? bandEl.textContent : '';
				var band = 'both';
				if (bt.indexOf('5G') >= 0 && bt.indexOf('双频') < 0) { band = '5g'; }
				else if (bt.indexOf('2.4G') >= 0 && bt.indexOf('双频') < 0) { band = '2g'; }
				// 与 renderTable / bindTableEvents 口径一致：按钮存在且 data-enabled !== '0' 才算启用
				var tg = tr.querySelector('[data-bind-toggle]');
				var en = !!(tg && tg.getAttribute('data-enabled') !== '0');
				var sel = tr.querySelector('[data-bind-select]');
				rows.push({
					idx: tr.getAttribute('data-row'),
					ssid: tr.getAttribute('data-ssid'),
					band: band,
					enabled: en,
					node_name: tr.getAttribute('data-node-name') || (sel ? sel.value : '') || ''
				});
			});
			updateStats(rows);
			bindTableEvents();
			restorePurityState();
			refreshPending();
		}
	}


	/* ---------------- 线路体检弹窗（照 ssidproxy 老版：横幅 + 出口/隐秘性/DNS + 来源脚注 + 底部结论） ---------------- */
	function showEnvDetail(d) {
		if (!d) { return; }
		var old = document.getElementById('tk-env-modal');
		if (old && old.parentNode) { old.parentNode.removeChild(old); }

		var mask = el('div', 'tk-modal-mask');
		mask.id = 'tk-env-modal';
		var box = el('div', 'tk-modal');

		var probe = d.probe || {};
		var dns = probe.dns || {};
		var lvl = d.env_level || (d.verdict === 'pass' ? 'ok' : (d.verdict === 'risk' ? 'warn' : 'err'));

		// 头部
		var head = el('div', 'tk-modal-head');
		head.appendChild(el('b', null, '线路体检 · ' + (d.ssid || '')));
		var x = el('button', 'tk-modal-x', '×');
		x.type = 'button';
		x.addEventListener('click', function () { mask.parentNode.removeChild(mask); });
		head.appendChild(x);
		box.appendChild(head);

		var body = el('div', 'tk-modal-body');

		// 顶部横幅（老版三段固定文案）
		var banner = el('div', 'tk-env-banner');
		banner.style.margin = '0.6rem 0 0.2rem';
		banner.style.padding = '0.6rem 0.8rem';
		banner.style.borderRadius = '6px';
		banner.style.fontSize = '13px';
		banner.style.lineHeight = '1.7';
		var sub = el('div', null);
		sub.style.fontSize = '12px';
		sub.style.opacity = '0.85';
		if (lvl === 'ok') {
			banner.style.background = '#eaf7ee';
			banner.style.border = '1px solid #bfe3c8';
			banner.style.color = '#1f8a3b';
			banner.appendChild(el('b', null, '✓ 已达到 TikTok 运营环境，可以放心使用'));
			sub.textContent = '出口 IP 正常、DNS 与出口同国且全程经代理、防泄漏自检通过、IP 为住宅段且未被标记代理。';
		} else if (lvl === 'warn') {
			banner.style.background = '#fff8e6';
			banner.style.border = '1px solid #f0dca8';
			banner.style.color = '#b26a00';
			banner.appendChild(el('b', null, '△ 网络链路合规，但 IP 质量不达标：' + (d.env_risk || '')));
			sub.textContent = 'DNS / IPv6 / 防泄漏都没问题，问题在出口 IP 属于机房段或被公开标记为代理，TikTok 运营风险高。建议换住宅 IP 节点。';
		} else {
			banner.style.background = '#fdecea';
			banner.style.border = '1px solid #f3c2bd';
			banner.style.color = '#b03a2e';
			banner.appendChild(el('b', null, '✗ 未达到 TikTok 运营环境'));
			sub.textContent = d.env_miss || '未取到出口 IP';
		}
		banner.appendChild(sub);
		body.appendChild(banner);

		// 区段一：出口
		body.appendChild(el('div', 'tk-sec', '出口'));
		var kv1 = el('div', 'tk-kv');
		function kvRow(k, v) {
			kv1.appendChild(el('span', 'k', k));
			kv1.appendChild(el('span', 'v', v));
		}
		kvRow('出口 IP', probe.ip ? probe.ip : '探测失败');
		var ccText = '—';
		if (probe.cc) {
			ccText = (probe.country && probe.country !== probe.cc) ? (probe.country + ' ' + probe.cc) : probe.cc;
		}
		kvRow('国家/地区', ccText);
		kvRow('运营商', probe.isp || probe.asn || '—');
		kvRow('延迟', probe.latency_ms ? (probe.latency_ms + ' ms') : '—');
		body.appendChild(kv1);

		// 区段二：隐秘性（三态：true=机房红 / false=住宅绿 / unknown=未确认灰）
		body.appendChild(el('div', 'tk-sec', '隐秘性'));
		var kv2 = el('div', 'tk-kv');

		kv2.appendChild(el('span', 'k', 'IP 类型'));
		var hs = probe.hosting;
		var hsSpan = el('span', 'v');
		hsSpan.appendChild(el('span', 'tk-tag ' + (hs === 'true' ? 'err' : (hs === 'false' ? 'ok' : 'na')),
			hs === 'true' ? '机房 IP' : (hs === 'false' ? '住宅/ISP IP' : '—')));
		kv2.appendChild(hsSpan);

		kv2.appendChild(el('span', 'k', '代理标记'));
		var ps = probe.proxy_flag;
		var psSpan = el('span', 'v');
		psSpan.appendChild(el('span', 'tk-tag ' + (ps === 'true' ? 'err' : (ps === 'false' ? 'ok' : 'na')),
			ps === 'true' ? '被标记为代理' : (ps === 'false' ? '未标记' : '—')));
		kv2.appendChild(psSpan);

		kv2.appendChild(el('span', 'k', 'ASN'));
		kv2.appendChild(el('span', 'v', probe.asn || '—'));

		body.appendChild(kv2);

		// 人工覆盖按钮（独立一行，放在 DNS 之后、数据来源之前）
		var overrideRow = el('div', null);
		overrideRow.style.display = 'flex';
		overrideRow.style.flexWrap = 'wrap';
		overrideRow.style.alignItems = 'center';
		overrideRow.style.gap = '0.5rem';
		overrideRow.style.marginTop = '0.8rem';
		overrideRow.style.paddingTop = '0.8rem';
		overrideRow.style.borderTop = '1px solid #eef1f6';

		if (d.override === 1 || d.override === '1') {
			// 已标记：显示「已人工标记」徽章 + 公网判定说明 + 取消按钮
			var overrideLabel = el('span', 'k', '人工标记');
			overrideRow.appendChild(overrideLabel);
			var overrideValue = el('span', 'v');
			overrideValue.appendChild(el('span', 'tk-tag ok', '已人工标记'));
			overrideRow.appendChild(overrideValue);

			if (d.raw_quality) {
				var rawLabel = el('span', 'k', '公网判定');
				overrideRow.appendChild(rawLabel);
				var rawValue = el('span', 'v');
				var rawTypeText = (d.raw_quality === 'cloud') ? '云机房IP' :
					(d.raw_quality === 'transit') ? '企业骨干IP' :
					(d.raw_quality === 'residential') ? '住宅IP' : '未知';
				rawValue.textContent = rawTypeText + '（已人工覆盖）';
				rawValue.style.color = '#999';
				overrideRow.appendChild(rawValue);
			}

			var cancelBtn = el('button', 'cbi-button tk-btn-sm', '取消住宅标记');
			cancelBtn.type = 'button';
			cancelBtn.style.marginTop = '0.5rem';
			cancelBtn.addEventListener('click', function () {
				if (cancelBtn.disabled) { return; }
				cancelBtn.disabled = true;
				cancelBtn.textContent = '处理中…';
				post('purity_override', { line: d.line || d.lineNum, value: '0' }).then(function (r) {
					if (!r || !r.ok) {
						cancelBtn.disabled = false;
						cancelBtn.textContent = '取消住宅标记';
						alert((r && r.msg) || '取消失败');
						return;
					}
					mask.parentNode.removeChild(mask);
					// 自动重新触发该行检测
					var checkBtn = document.querySelector('.tk-btn-check[data-line="' + (d.line || d.lineNum) + '"]');
					if (checkBtn) { checkBtn.click(); }
				}).catch(function () {
					cancelBtn.disabled = false;
					cancelBtn.textContent = '取消住宅标记';
					alert('请求失败');
				});
			});
			overrideRow.appendChild(cancelBtn);
		} else {
			// 未标记：显示「标记为住宅（覆盖判定）」按钮
			var markBtn = el('button', 'cbi-button cbi-button-apply tk-btn-sm', '标记为住宅（覆盖判定）');
			markBtn.type = 'button';
			markBtn.addEventListener('click', function () {
				if (markBtn.disabled) { return; }
				markBtn.disabled = true;
				markBtn.textContent = '处理中…';
				post('purity_override', { line: d.line || d.lineNum, value: '1' }).then(function (r) {
					if (!r || !r.ok) {
						markBtn.disabled = false;
						markBtn.textContent = '标记为住宅（覆盖判定）';
						alert((r && r.msg) || '标记失败');
						return;
					}
					mask.parentNode.removeChild(mask);
					// 自动重新触发该行检测
					var checkBtn = document.querySelector('.tk-btn-check[data-line="' + (d.line || d.lineNum) + '"]');
					if (checkBtn) { checkBtn.click(); }
				}).catch(function () {
					markBtn.disabled = false;
					markBtn.textContent = '标记为住宅（覆盖判定）';
					alert('请求失败');
				});
			});
			overrideRow.appendChild(markBtn);
		}
		// 区段三：DNS
		body.appendChild(el('div', 'tk-sec', 'DNS'));
		var kv3 = el('div', 'tk-kv');

		kv3.appendChild(el('span', 'k', '上游 DNS'));
		kv3.appendChild(el('span', 'v', dns.upstream || '1.1.1.1:53'));

		kv3.appendChild(el('span', 'k', '解析方式'));
		kv3.appendChild(el('span', 'v', dns.mode || '经该线路代理解析'));

		kv3.appendChild(el('span', 'k', '经代理解析'));
		var dnsVp = el('span', 'v');
		dnsVp.appendChild(el('span', 'tk-tag ' + (dns.via_proxy === 'true' ? 'ok' : 'err'), dns.via_proxy === 'true' ? '是' : '否'));
		kv3.appendChild(dnsVp);

		kv3.appendChild(el('span', 'k', '解析侧国家'));
		kv3.appendChild(el('span', 'v', dns.loc || '—'));

		kv3.appendChild(el('span', 'k', '与出口一致'));
		var dnsMt = el('span', 'v');
		dnsMt.appendChild(el('span', 'tk-tag ' + (dns.match === 'true' ? 'ok' : (dns.match === 'false' ? 'err' : 'na')),
			dns.match === 'true' ? '一致' : (dns.match === 'false' ? '不一致' : '—')));
		kv3.appendChild(dnsMt);

		body.appendChild(kv3);

		// 人工覆盖行（DNS 之后，独立一行）
		body.appendChild(overrideRow);

		// 数据来源脚注（老版口径）
		var src = el('div', 'tk-modal-src');
		src.textContent = '数据来源：出口 IP / 机房·住宅·代理标记 / ASN —— ipinfo.io（HTTPS）与 ip-api（机房、代理标记三态）；'
			+ '解析侧国家 —— Cloudflare 1.1.1.1/cdn-cgi/trace 经该线路 probe 口查询；'
			+ '延迟 —— 经该线路 probe 口实测 3 次首字节取中位数；DNS 上游 —— 路由器实际配置。';
		body.appendChild(src);

		box.appendChild(body);

		// 底部：一句话结论（老版「探测成功：…」，按 level 着色）+ 关闭

		var ft = el('div', 'tk-modal-ft');
		var foot = el('span', null, d.summary || '');
		foot.style.marginRight = 'auto';
		foot.style.fontSize = '12px';
		foot.style.color = (lvl === 'ok') ? '#1f8a3b' : (lvl === 'warn' ? '#b26a00' : '#b03a2e');
		ft.appendChild(foot);
		var btn = el('button', 'cbi-button', '关闭');
		btn.type = 'button';
		btn.addEventListener('click', function () { mask.parentNode.removeChild(mask); });
		ft.appendChild(btn);
		box.appendChild(ft);

		mask.appendChild(box);
		mask.addEventListener('click', function (ev) {
			if (ev.target === mask) { mask.parentNode.removeChild(mask); }
		});
		document.body.appendChild(mask);
	}

	/* ---------------- 插件可用性自检（原预检） ---------------- */
	function postPreflight(cmd, extra) {
		var body = new URLSearchParams();
		body.set('token', token);
		body.set('cmd', cmd);
		if (extra) { Object.keys(extra).forEach(function (k) { body.set(k, extra[k]); }); }
		return fetch(base + '/preflight_op', {
			method: 'POST',
			credentials: 'same-origin',
			cache: 'no-store',
			headers: { 'Content-Type': 'application/x-www-form-urlencoded; charset=UTF-8' },
			body: body.toString()
		}).then(function (r) {
			if (!r.ok) { throw new Error('HTTP ' + r.status); }
			return r.json();
		});
	}

	function bindCoreCheck() {
		var btn = $('[data-tk-act="core-check"]');
		if (!btn) { return; }
		var outBox = $('[data-core-out]');
		var listBox = $('[data-core-list]');
		var fixBtn = $('[data-tk-act="core-fix"]');

		function runCheck() {
			btn.disabled = true;
			if (outBox) { outBox.textContent = '自检中…'; outBox.className = 'tk-verdict is-idle'; }
			postPreflight('preflight_run').then(function (res) {
				btn.disabled = false;
				var data = (res && res.data) ? res.data : null;
				if (!res || res.success === false || !data) {
					if (outBox) {
						outBox.textContent = '自检失败：' + ((res && (res.error || res.msg)) || '预检模块未响应');
						outBox.className = 'tk-verdict is-bad';
					}
					return;
				}
				var sum = data.summary || {};
				var items = data.items || [];
				if (outBox) {
					outBox.textContent = '阻断 ' + (sum.block || 0) + ' 项 / 警告 ' + (sum.warn || 0) + ' 项 / 通过 ' + (sum.pass || 0) + ' 项';
					outBox.className = 'tk-verdict ' + ((sum.block > 0) ? 'is-bad' : (sum.warn > 0 ? 'is-pending' : 'is-online'));
				}
				if (listBox) {
					clear(listBox);
					var fixables = [];
					var actionSeen = {};
					items.forEach(function (it) {
						var lv = it.level || 'pass';
						var row = el('div', 'tk-core-item ' +
							(lv === 'pass' ? 'is-pass' : (lv === 'warn' ? 'is-warn' : 'is-block')));
						// 状态点
						row.appendChild(el('span', 'tk-core-dot', lv === 'pass' ? '✓' : (lv === 'warn' ? '!' : '✗')));
						// 名称
						row.appendChild(el('span', 'tk-core-name', it.title || ''));
						// 说明
						row.appendChild(el('span', 'tk-core-detail', it.detail || ''));
						listBox.appendChild(row);
						// 可修复动作收集（opkg:/svc:/trim/clean）
						if (lv !== 'pass' && it.fix) {
							it.fix.split(/[,;\s]+/).forEach(function (a) {
								if (a && !actionSeen[a]) { actionSeen[a] = true; fixables.push(a); }
							});
						}
					});
					listBox.hidden = false;
					if (fixBtn) {
						if (fixables.length > 0) {
							fixBtn.hidden = false;
							fixBtn.__actions = fixables.join(',');
							fixBtn.textContent = '一键修复（' + fixables.length + ' 项，如自动安装缺失核心）';
						} else {
							fixBtn.hidden = true;
						}
					}
				}
			}).catch(function (e) {
				btn.disabled = false;
				if (outBox) {
					outBox.textContent = '自检请求失败：' + e.message;
					outBox.className = 'tk-verdict is-bad';
				}
			});
		}
		btn.addEventListener('click', runCheck);

		if (fixBtn) {
			fixBtn.addEventListener('click', function () {
				var acts = fixBtn.__actions || '';
				if (!acts) { return; }
				var human = acts.split(',').map(function (a) {
					if (a.indexOf('opkg:') === 0) { return '安装 ' + a.slice(5); }
					if (a.indexOf('svc:') === 0) { return '重启 ' + a.slice(4); }
					if (a === 'trim') { return '停用超出名额的线路'; }
					if (a === 'clean') { return '清理残留'; }
					return a;
				}).join('\n  ');
				if (!armConfirm(fixBtn, {
					armText: '再点一次开始修复',
					restoreText: '一键修复',
					onConfirm: function () { /* 继续执行修复 */ }
				})) { return; }
				fixBtn.disabled = true;
				if (outBox) { outBox.textContent = '正在修复…'; outBox.className = 'tk-verdict is-idle'; }
				postPreflight('preflight_fix', { actions: acts }).then(function (res) {
					fixBtn.disabled = false;
					// 修复完自动重跑一次自检，这块区域立刻显示最新状态（无需手动刷新）
					setTimeout(function () { try { runCheck(); } catch (e) { console.warn(e); } }, 500);
					var results = (res && res.results) || [];
					var okN = 0, badN = 0, lines = [];
					results.forEach(function (r2) {
						if (r2.success) { okN++; } else { badN++; }
						lines.push((r2.success ? '✓ ' : '✗ ') + (r2.action || '') + '：' + (r2.msg || ''));
					});
					if (outBox) {
						outBox.textContent = '修复完成：成功 ' + okN + ' 项，失败 ' + badN + ' 项　（可再点「开始自检」复验）';
						outBox.className = 'tk-verdict ' + (badN > 0 ? 'is-bad' : 'is-online');
					}
				}).catch(function () {
					fixBtn.disabled = false;
					if (outBox) { outBox.textContent = '修复请求失败'; outBox.className = 'tk-verdict is-bad'; }
				});
		});
		}
	}

	/* ---------------- 开箱自检状态条（t_d32788de） ---------------- */
	/* 数据源：/etc/tkproxy/bootcheck.json（bootcheck.sh 落盘），经 bootcheck_state 接口读出。
	   block=0&&warn=0 绿「待机 · 可直接使用」；block=0&&warn>0 黄「可用（N 项提醒）」；
	   block>0 红「不可用：<第一条阻断项>」+ 一键修复；没跑过灰「未自检」+ 立即自检。 */
	function bindBootbar() {
		var bar = $('[data-bootbar]');
		if (!bar) { return; }
		var dotEl = $('[data-bootbar-dot]', bar);
		var textEl = $('[data-bootbar-text]', bar);
		var subEl = $('[data-bootbar-sub]', bar);
		var runBtn = $('[data-bootbar-run]', bar);
		var detailBtn = $('[data-bootbar-detail]', bar);
		var fixBtn = $('[data-bootbar-fix]', bar);
		var listBox = $('[data-bootbar-list]');

		function setBar(level, text, sub) {
			bar.className = 'tk-bootbar is-' + level;
			setText(textEl, text);
			setText(subEl, sub || '');
			bar.hidden = false;
		}

		function render(st) {
			if (!st || st.ran !== true) {
				var corrupt = st && st.corrupted === true;
				setBar('idle', corrupt ? '自检数据损坏' : '未自检',
					corrupt ? '结果文件解析失败，点「立即自检」重新生成' : '还没跑过开箱自检');
				if (runBtn) { runBtn.hidden = false; }
				if (detailBtn) { detailBtn.hidden = true; }
				if (fixBtn) { fixBtn.hidden = true; }
				if (listBox) { listBox.hidden = true; }
				return;
			}
			var block = st.block || 0, warn = st.warn || 0;
			var items = st.items || [];
			var firstBlock = null;
			items.forEach(function (it) {
				if (!firstBlock && (it.level === 'block')) { firstBlock = it; }
			});
			if (detailBtn) { detailBtn.hidden = items.length === 0; }
			if (fixBtn) {
				var fixables = [];
				var seen = {};
				items.forEach(function (it) {
					if (it.level !== 'pass' && it.fix) {
						it.fix.split(/[,;\s]+/).forEach(function (a) {
							if (a && !seen[a]) { seen[a] = true; fixables.push(a); }
						});
					}
				});
				fixBtn.__actions = fixables.join(',');
				fixBtn.hidden = fixables.length === 0;
			}
			if (block > 0) {
				setBar('bad', '不可用：' + ((firstBlock && (firstBlock.title || firstBlock.detail)) || '存在阻断项'),
					'共 ' + block + ' 项阻断' + (warn > 0 ? '、' + warn + ' 项提醒' : '') + '，可点「一键修复」尝试自动修复');
			} else if (warn > 0) {
				setBar('warn', '可用（' + warn + ' 项提醒）', '点「查看明细」看具体提醒；不影响使用');
			} else {
				setBar('ok', '待机 · 可直接使用', '自检全部通过（' + (st.pass || 0) + ' 项）');
			}
		}

		function renderList(st) {
			if (!listBox) { return; }
			if (listBox.hidden) {
				clear(listBox);
				var items = (st && st.items) || [];
				items.forEach(function (it) {
					var lv = it.level || 'pass';
					var row = el('div', 'tk-core-item ' +
						(lv === 'pass' ? 'is-pass' : (lv === 'warn' ? 'is-warn' : 'is-block')));
					row.appendChild(el('span', 'tk-core-dot', lv === 'pass' ? '✓' : (lv === 'warn' ? '!' : '✗')));
					row.appendChild(el('span', 'tk-core-name', it.title || ''));
					row.appendChild(el('span', 'tk-core-detail', it.detail || ''));
					listBox.appendChild(row);
				});
				listBox.hidden = false;
			} else {
				listBox.hidden = true;
			}
		}

		function load() {
			post('bootcheck_state', {}).then(function (res) {
				render(res && res.ok ? res : null);
				bar.__state = res || null;
			}).catch(function () {
				setBar('idle', '未自检', '自检状态读取失败');
				if (runBtn) { runBtn.hidden = false; }
				if (detailBtn) { detailBtn.hidden = true; }
				if (fixBtn) { fixBtn.hidden = true; }
			});
		}

		if (runBtn) {
			runBtn.addEventListener('click', function () {
				runBtn.disabled = true;
				setBar('idle', '自检中…', '约需 10-20 秒（含出网探测）');
				post('bootcheck_run', {}).then(function (res) {
					runBtn.disabled = false;
					if (!res || res.ok !== true) {
						setBar('idle', '自检失败', (res && res.msg) || '自检脚本未响应，请稍后重试');
						return;
					}
					if (runBtn) { runBtn.hidden = true; }
					render(res);
					bar.__state = res;
					if (listBox && !listBox.hidden) { renderList(res); }
				}).catch(function (e) {
					runBtn.disabled = false;
					setBar('idle', '自检请求失败', e.message || '');
				});
			});
		}
		if (detailBtn) {
			detailBtn.addEventListener('click', function () {
				renderList(bar.__state);
			});
		}
		if (fixBtn) {
			fixBtn.addEventListener('click', function () {
				var acts = fixBtn.__actions || '';
				if (!acts) { return; }
				if (!armConfirm(fixBtn, {
					armText: '再点一次开始修复',
					restoreText: '一键修复',
					onConfirm: function () { /* 继续执行修复 */ }
				})) { return; }
				fixBtn.disabled = true;
				setBar('idle', '正在修复…', '可能需要安装缺失依赖，请勿断电');
				postPreflight('preflight_fix', { actions: acts }).then(function (res) {
					fixBtn.disabled = false;
					var results = (res && res.results) || [];
					var badN = 0;
					results.forEach(function (r2) { if (!r2.success) { badN++; } });
					if (badN > 0) {
						setBar('warn', '修复未全部成功', badN + ' 项失败，可点「查看明细」后手动「开始自检」复验');
					}
					// 无论成败都强制重跑一次自检刷新状态条
					post('bootcheck_run', {}).then(function (res2) {
						bar.__state = res2 || null;
						render(res2 && res2.ok === true ? res2 : null);
						if (listBox && !listBox.hidden && res2) { renderList(res2); }
					}).catch(function () { load(); });
				}).catch(function () {
					fixBtn.disabled = false;
					setBar('warn', '修复请求失败', '可稍后重试');
				});
			});
		}

		load();
	}

	/* ---------------- 授权（卡密） ---------------- */
	function bindLicense() {
		var badge = $('[data-lic-badge]');
		var machineEl = $('[data-lic-machine]');
		var cardEl = $('[data-lic-card]');
		var expEl = $('[data-lic-exp]');
		var verEl = $('[data-lic-ver]');
		var outEl = $('[data-lic-out]');
		if (!badge) { return; }

		function fmtDate(ts) {
			if (!ts || Number(ts) <= 0) { return '不限期'; }
			var d = new Date(Number(ts) * 1000);
			return d.getFullYear() + '-' + ('0' + (d.getMonth() + 1)).slice(-2) + '-' + ('0' + d.getDate()).slice(-2);
		}

		function render(st) {
			if (!st) { return; }
			$all('[data-lic-machine]').forEach(function (n) { n.textContent = st.machine || '—'; });
			$all('[data-lic-ver]').forEach(function (n) { n.textContent = st.version || '—'; });
			$all('[data-lic-badge]').forEach(function (n) {
				var on2 = st.activated === true, bad2 = on2 && st.expired === true;
				n.textContent = !on2 ? '未激活' : (bad2 ? '授权异常' : '已激活 · 永久');
				n.className = (on2 && !bad2) ? 'is-online' : 'is-bad';
			});
			$all('[data-lic-card]').forEach(function (n) { n.textContent = st.card_mask || (st.activated === true ? '已激活' : '—'); });
			$all('[data-lic-exp]').forEach(function (n) {
				n.textContent = st.activated === true ? '永久（绑定本机）' : '—';
			});
			var on = st.activated === true;
			var bad = on && st.expired === true;
			if (badge) {
				badge.textContent = !on ? '未激活' : (bad ? '授权异常' : '已激活 · 永久');
				badge.className = (on && !bad) ? 'is-online' : 'is-bad';
			}
		}

		function load() {
			return post('license_status').then(function (r) {
				if (r && r.data) { render(r.data); }
				return r;
			}).catch(function () {
				if (badge) { badge.textContent = '读取失败'; badge.className = 'tk-card-meta is-bad'; }
			});
		}

		function say(cls, text) {
			if (!outEl) { return; }
			outEl.textContent = text;
			outEl.className = 'tk-verdict ' + cls;
		}

		var btnA = $('[data-tk-act="lic-activate"]');
		if (btnA) {
			btnA.addEventListener('click', function () {
				var inp = $('#tk-lic-input');
				var card = inp ? (inp.value || '').trim() : '';
				if (!card) { say('is-bad', '请先粘贴卡密'); return; }
				btnA.disabled = true;
				say('is-idle', '正在激活…');
				post('license_activate', { card: card }).then(function (r) {
					btnA.disabled = false;
					if (r && r.data) { render(r.data); }
					if (r && r.ok) {
						say('is-online', r.msg || '激活成功');
						if (inp) { inp.value = ''; }
					} else {
						say('is-bad', (r && r.msg) || '激活失败');
					}
				}).catch(function () { btnA.disabled = false; say('is-bad', '激活失败'); });
			});
		}

		var btnV = $('[data-tk-act="lic-verify"]');
		if (btnV) {
			btnV.addEventListener('click', function () {
				btnV.disabled = true;
				say('is-idle', '正在校验…');
				post('license_verify').then(function (r) {
					btnV.disabled = false;
					if (r && r.data) { render(r.data); }
					say((r && r.ok) ? 'is-online' : 'is-bad', (r && r.msg) || '校验完成');
				}).catch(function () { btnV.disabled = false; say('is-bad', '校验请求失败'); });
			});
		}

		var btnR = $('[data-tk-act="lic-reset"]');
		if (btnR) {
			btnR.addEventListener('click', function () {
				if (!armConfirm(btnR, {
					armText: '再点一次清除授权',
					restoreText: '清除授权',
					onConfirm: function () { /* 继续 */ }
				})) { return; }
				btnR.disabled = true;
				post('license_reset').then(function (r) {
					btnR.disabled = false;
					if (r && r.data) { render(r.data); }
					say((r && r.ok) ? 'is-pending' : 'is-bad', (r && r.msg) || '已处理');
				}).catch(function () { btnR.disabled = false; say('is-bad', '清除请求失败'); });
			});
		}

		load();
	}

	/* ---------------- 云端更新 ---------------- */
	function bindUpdater() {
		var btnCheck = $('[data-tk-act="upd-check"]');
		var btnInstall = $('[data-tk-act="upd-install"]');
		var latestEl = $('[data-upd-latest]');
		var outEl = $('[data-upd-out]');
		if (!btnCheck) { return; }

		function say(cls, text) {
			if (!outEl) { return; }
			outEl.textContent = text || '';
			outEl.className = 'tk-verdict ' + (cls || '');
		}

		function renderLatest(txt, cls) {
			$all('[data-upd-latest]').forEach(function (n) {
				n.textContent = txt;
				n.className = cls || '';
			});
		}

		/* 升级弹窗：检查到新版本 → 弹「有新版本请升级」→ 点升级自动更新 */
		function showUpdateModal(info) {
			var old = document.getElementById('tk-upd-modal');
			if (old && old.parentNode) { old.parentNode.removeChild(old); }

			var mask = el('div', 'tk-modal-mask');
			mask.id = 'tk-upd-modal';
			var box = el('div', 'tk-modal tk-upd-modal-box');

			var head = el('div', 'tk-modal-head');
			head.appendChild(el('b', null, '有新版本请升级'));
			box.appendChild(head);

			var body = el('div', 'tk-modal-body');
			var line1 = el('p', 'tk-upd-line');
			line1.textContent = '当前版本 ' + (info.current || '?') + '　→　最新版本 ' + (info.latest || '?');
			body.appendChild(line1);
			if (info.notes) {
				var line2 = el('p', 'tk-upd-notes');
				line2.textContent = info.notes;
				body.appendChild(line2);
			}
			var line3 = el('p', 'tk-upd-tip');
			line3.textContent = '升级会自动下载并校验签名与 SHA256，装完自动刷新页面；过程中 WiFi 不会中断。';
			body.appendChild(line3);
			var prog = el('p', 'tk-verdict');
			body.appendChild(prog);
			box.appendChild(body);


		var ft = el('div', 'tk-modal-ft');
			var later = el('button', 'cbi-button', '稍后再说');
			later.type = 'button';
			var go = el('button', 'cbi-button cbi-button-apply', '立即升级');
			go.type = 'button';
			ft.appendChild(later);
			ft.appendChild(go);
			box.appendChild(ft);
			mask.appendChild(box);

			function close() { if (mask.parentNode) { mask.parentNode.removeChild(mask); } }
			later.addEventListener('click', close);

			go.addEventListener('click', function () {
				go.disabled = true;
				later.disabled = true;
				prog.className = 'tk-verdict is-idle';
				prog.textContent = '正在下载并校验…';
				post('update_install').then(function (r) {
					if (r && r.ok) {
						prog.className = 'tk-verdict is-online';
						prog.textContent = (r.msg || '升级完成') + '，正在刷新页面…';
						setTimeout(function () { window.location.reload(); }, 1200);
					} else {
						go.disabled = false;
						later.disabled = false;
						prog.className = 'tk-verdict is-bad';
						prog.textContent = (r && r.msg) || '升级失败';
					}
				}).catch(function () {
					go.disabled = false;
					later.disabled = false;
					prog.className = 'tk-verdict is-bad';
					prog.textContent = '升级请求失败（网络或超时）';
				});
			});

			document.body.appendChild(mask);
			go.focus();
		}

		btnCheck.addEventListener('click', function () {
			btnCheck.disabled = true;
			say('is-idle', '正在检查…');
			post('update_check').then(function (r) {
				btnCheck.disabled = false;
				if (!r || r.ok === false) {
					say('is-bad', (r && r.msg) || '检查失败');
					renderLatest('检查失败', 'is-bad');
					return;
				}
				say(r.has_update ? 'is-pending' : 'is-online',
					(r.has_update ? '发现新版本 ' + r.latest : '已是最新（' + r.current + '）') +
					(r.notes ? '（' + r.notes + '）' : ''));
				// 只有真有新版本才显示云端版本号；否则显示当前版本，
				// 避免更新源清单停留在旧版时把旧号当「最新版本」误导（版本误报）
				renderLatest(
					r.has_update ? (r.latest || '—') : (r.current || '—'),
					r.has_update ? 'is-bad' : 'is-online');
				if (btnInstall) {
					btnInstall.hidden = !r.has_update;
					btnInstall.textContent = '立即更新到 ' + (r.latest || '');
				}
				if (r.has_update) { showUpdateModal(r); }
			}).catch(function () {
				btnCheck.disabled = false;
				say('is-bad', '检查请求失败');
			});
		});

		/* 打开页面静默检查一次：有新版本就直接弹窗（同一会话只弹一次） */
		try {
			if (!sessionStorage.getItem('tk-upd-prompted')) {
				post('update_check').then(function (r) {
					if (r && r.ok && r.has_update) {
						sessionStorage.setItem('tk-upd-prompted', '1');
						renderLatest(r.latest || '—', 'is-bad');
						showUpdateModal(r);
					} else if (r && r.ok) {
						// 无更新时展示当前版本，不把云端（可能更旧的）版本号当「最新」
						renderLatest(r.current || '—', 'is-online');
					}
				}).catch(function () { /* 静默 */ });
			}
		} catch (e) { /* 隐私模式下 sessionStorage 可能不可用 */ }

		if (btnInstall) {
			btnInstall.addEventListener('click', function () {
				if (!armConfirm(btnInstall, {
					armText: '再点一次开始更新',
					restoreText: btnInstall.textContent,
					onConfirm: function () { /* 继续 */ }
				})) { return; }
				btnInstall.disabled = true;
				btnCheck.disabled = true;
				say('is-idle', '正在下载并安装（会校验签名与 SHA256）…');
				post('update_install').then(function (r) {
					btnInstall.disabled = false;
					btnCheck.disabled = false;
					if (r && r.ok) {
						say('is-online', (r.msg || '更新完成') + '，正在刷新页面…');
						setTimeout(function () { window.location.reload(); }, 1500);
					} else {
						say('is-bad', (r && r.msg) || '更新失败');
					}
				}).catch(function () {
					btnInstall.disabled = false;
					btnCheck.disabled = false;
					say('is-bad', '更新请求失败');
				});
			});
		}
	}

	if (page === 'dashboard') { bindDashboard(); bindWorkbench(); bindCoreCheck(); bindBootbar(); bindLicense(); bindUpdater(); }

	/* 页面进来就先算一次『未部署改动』，不依赖表格是否重绘 */
	if (page === 'dashboard' && typeof refreshPending === 'function') {
		if (document.readyState === 'loading') {
			document.addEventListener('DOMContentLoaded', refreshPending);
		} else {
			refreshPending();
		}
	}
	if (page === 'ports') { bindPorts(); bindBatch(); }
	if (page === 'nodes') { bindNodes(); }
	/* t_299f5f62：SOCKS5 独立页也用 data-tk-page="nodes" 标记，
	 * 复用导入/删除/订阅拉取与 socks5 添加逻辑；模板里没有对应区块时这些绑定自动跳过 */
	if (page === 'nodes') { bindSocks5(); }
	if (page === 'edit') { bindEdit(); }
	if (page === 'purity') { bindPurity(); }
})();
