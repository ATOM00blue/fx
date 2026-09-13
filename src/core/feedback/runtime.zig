const std = @import("std");

pub const url = "https://layerx1.com/feedback";

test "feedback URL stays on the LayerX1 domain" {
    try std.testing.expectEqualStrings("https://layerx1.com/feedback", url);
}
