/* IronVeil Security – two-factor setup on the profile screen. */
( function () {
	'use strict';
	var cfg = window.IronVeil2FA || {};
	var box = document.querySelector( '.ironveil-2fa-box' );
	if ( ! box ) {
		return;
	}
	var msg = box.querySelector( '.ironveil-2fa-msg' );

	function say( text, ok ) {
		msg.textContent = text || '';
		msg.className = 'ironveil-2fa-msg ' + ( ok ? 'is-ok' : 'is-err' );
	}

	function call( action, data ) {
		var body = new URLSearchParams();
		body.append( 'action', action );
		body.append( 'nonce', cfg.nonce );
		Object.keys( data || {} ).forEach( function ( k ) { body.append( k, data[ k ] ); } );
		return fetch( cfg.ajax, { method: 'POST', credentials: 'same-origin', body: body } ).then( function ( r ) { return r.json(); } );
	}

	function codeValue() {
		var i = box.querySelector( '.ironveil-2fa-code' );
		return i ? i.value.replace( /\s+/g, '' ) : '';
	}

	function showCodes( codes ) {
		var wrap = document.createElement( 'div' );
		wrap.className = 'ironveil-codes';
		var p = document.createElement( 'p' );
		p.textContent = cfg.i18n.saveCodes;
		var pre = document.createElement( 'pre' );
		pre.textContent = codes.join( '\n' );
		wrap.appendChild( p );
		wrap.appendChild( pre );
		box.innerHTML = '';
		box.appendChild( wrap );
	}

	box.addEventListener( 'click', function ( e ) {
		var t = e.target;
		if ( t.classList.contains( 'ironveil-2fa-begin' ) ) {
			e.preventDefault();
			call( 'ironveil_2fa_begin' ).then( function ( r ) {
				if ( ! r.success ) { return say( cfg.i18n.error ); }
				var setup = box.querySelector( '.ironveil-2fa-setup' );
				setup.hidden = false;
				t.hidden = true;
				box.querySelector( '.ironveil-secret' ).textContent = r.data.secret;
				var holder = box.querySelector( '.ironveil-qr' );
				holder.innerHTML = '';
				if ( window.qrcode ) {
					var qr = window.qrcode( 0, 'M' );
					qr.addData( r.data.uri );
					qr.make();
					holder.innerHTML = qr.createSvgTag( { cellSize: 4, margin: 2, scalable: true } );
				}
				var input = box.querySelector( '.ironveil-2fa-setup .ironveil-2fa-code' );
				if ( input ) { input.focus(); }
			} );
		}
		if ( t.classList.contains( 'ironveil-2fa-enable' ) ) {
			e.preventDefault();
			call( 'ironveil_2fa_enable', { code: codeValue() } ).then( function ( r ) {
				if ( ! r.success ) { return say( ( r.data && r.data.message ) || cfg.i18n.error ); }
				showCodes( r.data.codes );
			} );
		}
		if ( t.classList.contains( 'ironveil-2fa-recovery' ) ) {
			e.preventDefault();
			call( 'ironveil_2fa_recovery', { code: codeValue() } ).then( function ( r ) {
				if ( ! r.success ) { return say( ( r.data && r.data.message ) || cfg.i18n.error ); }
				showCodes( r.data.codes );
			} );
		}
		if ( t.classList.contains( 'ironveil-2fa-disable' ) ) {
			e.preventDefault();
			if ( ! window.confirm( cfg.i18n.confirmDisable ) ) { return; }
			var data = box.getAttribute( 'data-self' ) === '1' ? { code: codeValue() } : { user: box.getAttribute( 'data-user' ) };
			call( 'ironveil_2fa_disable', data ).then( function ( r ) {
				if ( ! r.success ) { return say( ( r.data && r.data.message ) || cfg.i18n.error ); }
				window.location.reload();
			} );
		}
	} );

	// Enter in a code field must not submit the whole profile form.
	box.addEventListener( 'keydown', function ( e ) {
		if ( e.key === 'Enter' && e.target.classList.contains( 'ironveil-2fa-code' ) ) {
			e.preventDefault();
			var btn = box.querySelector( '.ironveil-2fa-enable:not([hidden])' );
			if ( btn && btn.offsetParent !== null ) { btn.click(); }
		}
	} );
}() );
