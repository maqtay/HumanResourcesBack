package com.maqtay.HumanResourcesBack.payload.response;

public class MessageResponse {
    public String message;
    public MessageResponse(String s) {
        this.message = s;
    }

    public String getMessage() {
        return message;
    }

    public void setMessage(String message) {
        this.message = message;
    }
}
