$(document).ready(function() {
    // Auto-scroll to bottom of chat messages
    function scrollToBottom() {
        const chatMessages = document.getElementById('chat-messages');
        chatMessages.scrollTop = chatMessages.scrollHeight;
    }

    // Check for suspicious links
    function checkForSuspiciousLinks(message) {
        const links = message.match(/http[s]?:\/\/[^\s]+/g) || [];
        return links.filter(link => {
            const trustedDomains = ['facebook.com', 'google.com', 'instagram.com', 'youtube.com', 'twitter.com'];
            return !trustedDomains.some(domain => link.includes(domain));
        });
    }

    // Handle message form submission
    $('#message-form').on('submit', function(e) {
        e.preventDefault();
        
        const messageText = $('textarea[name="message"]').val().trim();
        const file = $('input[name="file"]')[0].files[0];
        
        // Check if message is empty and no file is selected
        if (!messageText && !file) {
            alert('Please enter a message or select a file');
            return;
        }

        // Check for suspicious links
        const suspiciousLinks = checkForSuspiciousLinks(messageText);
        if (suspiciousLinks.length > 0) {
            if (!confirm('Warning: This message contains suspicious links. Do you want to send it anyway?')) {
                return;
            }
        }

        // Create FormData object
        const formData = new FormData(this);

        // Send message using AJAX
        $.ajax({
            url: $(this).attr('action'),
            type: 'POST',
            data: formData,
            processData: false,
            contentType: false,
            success: function(response) {
                // Clear inputs
                $('textarea[name="message"]').val('');
                $('input[name="file"]').val('');
                
                // Reload chat messages
                $('#chat-messages').load(location.href + ' #chat-messages>*', function() {
                    scrollToBottom();
                });
            },
            error: function() {
                alert('Error sending message');
            }
        });
    });

    // Handle file input changes
    $('#file-input').on('change', function() {
        const file = this.files[0];
        if (file) {
            // Check file size (10MB limit)
            if (file.size > 10 * 1024 * 1024) {
                alert('File size must be less than 10MB');
                this.value = '';
                return;
            }

            // Check file type
            const allowedTypes = ['image/jpeg', 'image/png', 'image/gif', 'application/pdf', 'video/mp4', 'video/avi'];
            if (!allowedTypes.includes(file.type)) {
                alert('Invalid file type. Only images, PDFs, and videos are allowed.');
                this.value = '';
                return;
            }
        }
    });

    // Handle adding contacts
    $('#add-contact-form').on('submit', function(e) {
        e.preventDefault();
        const contactId = $('#new-contact-id').val().trim();
        
        if (!contactId) {
            alert('Please enter a contact ID');
            return;
        }

        $.ajax({
            url: '/add_contact',
            type: 'POST',
            data: { contact_id: contactId },
            success: function(response) {
                if (response.status === 'success') {
                    // Reload contacts list
                    $('#contact-list').load(location.href + ' #contact-list>*');
                    $('#new-contact-id').val('');
                    alert('Contact added successfully');
                } else {
                    alert('Error: ' + (response.message || 'Failed to add contact'));
                }
            },
            error: function() {
                alert('Error adding contact');
            }
        });
    });

    // Handle link warnings
    let currentUrl = '';
    let currentSender = '';

    $('.blurred-link').on('click', function() {
        currentUrl = $(this).data('url');
        currentSender = $(this).closest('.message').find('strong').text().replace(':', '');
        $('#warning-modal').show();
        $('#link-display').text('Link: ' + currentUrl).hide();
    });

    $('#view-link').on('click', function() {
        $('#link-display').show();
        $(this).text('Open Link');
        $(this).off('click').on('click', function() {
            window.open(currentUrl, '_blank');
        });
    });

    // Handle contact blocking
    $('#block-contact').on('click', function() {
        const contactId = currentSender;
        
        $.ajax({
            url: '/block_contact',
            type: 'POST',
            data: { contact_id: contactId },
            success: function(response) {
                if (response.status === 'success') {
                    alert('Contact blocked successfully');
                    location.reload();
                } else {
                    alert('Error: ' + (response.message || 'Failed to block contact'));
                }
            },
            error: function() {
                alert('Error blocking contact');
            }
        });
        $('#warning-modal').hide();
    });

    // Close modal
    $('.close').on('click', function() {
        $('#warning-modal').hide();
        $('#link-display').hide();
        $('#view-link').text('View Link');
    });

    // Initial scroll to bottom
    scrollToBottom();

    // Add observer for new messages
    const chatMessages = document.getElementById('chat-messages');
    const observer = new MutationObserver(function(mutations) {
        mutations.forEach(function(mutation) {
            if (mutation.type === 'childList') {
                scrollToBottom();
                // Add pulse animation to new message
                $('.message').last().css('animation', 'pulse 0.5s');
                setTimeout(function() {
                    $('.message').last().css('animation', '');
                }, 500);
            }
        });
    });

    observer.observe(chatMessages, {
        childList: true,
        subtree: true
    });
});