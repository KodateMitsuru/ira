// SPDX-License-Identifier: AGPL-3.0-or-later
package android.os;
public class Message {
    public int what;
    public Object obj;
    private Handler target;
    public Message(int what) { this.what = what; }
    public static Message obtain(Handler handler, int what, Object obj) {
        Message message = new Message(what);
        message.obj = obj;
        message.target = handler;
        return message;
    }
    public void sendToTarget() { target.enqueue(this); }
}
