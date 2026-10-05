/* IronVeil Security – admin UI (no dependencies). */
( function () {
	'use strict';
	var cfg = window.IronVeil || {};

	// Confirm destructive forms.
	document.addEventListener( 'submit', function ( e ) {
		var f = e.target;
		if ( f && f.getAttribute && f.getAttribute( 'data-confirm' ) && ! window.confirm( ( cfg.i18n && cfg.i18n.confirm ) || 'Are you sure?' ) ) {
			e.preventDefault();
		}
	}, true );

	var box = document.querySelector( '.iv-scan' );
	if ( ! box ) {
		return;
	}
	var startBtns = Array.prototype.slice.call( box.querySelectorAll( '.iv-scan-start' ) );
	var cancelBtn = box.querySelector( '.iv-scan-cancel' );
	var progress = box.querySelector( '.iv-progress' );
	var bar = box.querySelector( '.iv-bar span' );
	var stage = box.querySelector( '.iv-stage' );
	var busy = false;
	var stopped = false;

	function setDisabled( v ) {
		startBtns.forEach( function ( b ) { b.disabled = v; } );
	}

	function call( what, deep ) {
		var body = new URLSearchParams();
		body.append( 'action', 'ironveil_scan' );
		body.append( 'nonce', cfg.nonce );
		body.append( 'do', what );
		if ( deep ) { body.append( 'deep', '1' ); }
		return fetch( cfg.ajax, { method: 'POST', credentials: 'same-origin', body: body } )
			.then( function ( r ) { return r.json(); } )
			.then( function ( j ) {
				if ( ! j || ! j.success ) { throw new Error( 'request failed' ); }
				return j.data;
			} );
	}

	function render( p ) {
		progress.hidden = false;
		var pct = Math.max( 3, p.pct || 0 );
		bar.style.width = pct + '%';
		var label = ( cfg.i18n.stages && cfg.i18n.stages[ p.stage ] ) || p.stage;
		var c = p.counts || {};
		stage.textContent = label + ( p.deep ? ' (deep)' : '' ) + ' · ' + ( c.files || 0 ) + ' files · ' + ( c.analyzed || 0 ) + ' analysed · ' + ( c.skipped || 0 ) + ' unchanged' + ( p.clam ? ' · ClamAV ' + ( c.clamav || 0 ) : '' ) + ( p.message ? ' · ' + p.message : '' );
	}

	function loop() {
		if ( stopped ) { return; }
		call( 'step' ).then( function ( p ) {
			render( p );
			if ( p.running ) {
				setTimeout( loop, 400 );
			} else {
				done();
			}
		} ).catch( function () { setTimeout( loop, 3000 ); } );
	}

	function done() {
		busy = false;
		setDisabled( false );
		cancelBtn.hidden = true;
		setTimeout( function () { window.location.reload(); }, 900 );
	}

	startBtns.forEach( function ( btn ) {
		btn.addEventListener( 'click', function () {
			if ( busy ) { return; }
			busy = true;
			stopped = false;
			setDisabled( true );
			cancelBtn.hidden = false;
			call( 'start', btn.getAttribute( 'data-deep' ) === '1' ).then( function ( p ) { render( p ); loop(); } ).catch( function () { busy = false; setDisabled( false ); } );
		} );
	} );

	cancelBtn.addEventListener( 'click', function () {
		stopped = true;
		call( 'cancel' ).then( done );
	} );

	// Resume watching a scan already in progress (e.g. scheduled).
	if ( box.getAttribute( 'data-running' ) === '1' ) {
		busy = true;
		setDisabled( true );
		cancelBtn.hidden = false;
		loop();
	}
}() );
