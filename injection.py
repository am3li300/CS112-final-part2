    injection_1 = """
    <!-- INSERTED BY CS112 PROXY -->

    <html>
    <style>
        /* hide all elements except the cs112-container and toggle-button */
        .cs112-overlay-active body>*:not(.cs112-container):not(.cs112-toggle-button) {
            display: none !important;
        }

        .cs112-container {
            color: red !important;
        }

        .cs112-toggle-button {
            position: fixed;
            bottom: 20px;
            right: 20px;

            width: 300px;
            font-size: 16px;
            font-family: 'Inconsolata', monospace;
            font-weight: bold;
            background-color: #39883b;
            border: 1px solid #000000;
            color: white;
            padding: 15px 32px;
            text-align: center;
            text-decoration: none;
            display: inline-block;
            font-size: 16px;
            margin: 4px 2px;
            cursor: pointer;
            border-radius: 5px;
            z-index: 1000;
        }
    </style>


    <div class="cs112-container" style="display: none">
        <!-- START LLM CONTENT -->
    """

    injection_2 = """
    </div>
        <!-- END LLM CONTENT -->
    <button type="button" class="cs112-toggle-button">Enable CS112 Edits</button>

    <script>
        window.onload = function enableToggleButton() {
            const toggleButton = document.querySelector('.cs112-toggle-button');
            const cs112Container = document.querySelector('.cs112-container');

            toggleButton.addEventListener('click', () => {
                const active = document.documentElement.classList.toggle('cs112-overlay-active');

                if (active) {
                    // Show cs112 content
                    cs112Container.style.display = 'block';
                    toggleButton.textContent = 'Disable CS112 Edits';
                } else {
                    // Show original site
                    cs112Container.style.display = 'none';
                    toggleButton.textContent = 'Enable CS112 Edits';
                }
            });
        }
    </script>

    </html>
    <!-- END INSERT -->
    """